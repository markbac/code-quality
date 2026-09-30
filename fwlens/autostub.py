"""
Project-wide auto-stub loop for fwlens.

`debug-parse` already auto-fixes missing-header, undeclared-function, and missing-arch-
define errors, but only for one file at a time -- useful for diagnosing a single parse
failure, not for clearing every stub a whole project needs in one run. This module
generalises the same mechanism to the full in-scope file set: parse everything, aggregate
diagnostics across all of it, stub/patch what's needed, re-parse, repeat until nothing new
turns up (capped at a small round count -- meant to converge in 1-2 rounds for a real
project; if it doesn't, something bigger than a missing header is going on and
`debug-parse --file <name>` on a specific failure is the better next step).

Three diagnostic shapes are handled, matching debug-parse:

1. Missing header ('X.h' file not found) -> stub written to iar_stubs/. Every generated
   stub -- functional or empty -- unconditionally #includes a shared catchall header
   (_iar_builtins_stub.h) so that whichever header a translation unit happens to reach
   first still pulls in every undeclared-function prototype discovered so far. Earlier
   versions of this module tried to wire that catchall in via a single forwarding header
   (mimicking IAR's own intrinsics.h -> iccarm_builtin.h chain) -- that only works if the
   *real* intrinsics.h exists to do the forwarding, which it doesn't once it's itself a
   stub, so the chain silently went nowhere. Every stub self-including the catchall is
   more robust and doesn't depend on which specific header started the chain.

2. Undeclared function (call to undeclared function 'X') -> prototype appended to the
   shared catchall. A small curated list of well-known standard-library and CMSIS-intrinsic
   functions get their real signature; anything else gets an old-style, unprototyped
   declaration (`int fn();`) rather than a guessed fixed-arity one. An earlier version used
   a generic 4-parameter `unsigned int fn(unsigned int, unsigned int, unsigned int,
   unsigned int)` prototype for everything -- clang treats a *wrong* prototype as
   authoritative once it's visible, so a real 3-argument `memcpy(dest, src, n)` call site
   started failing with "too few arguments to function call, expected 4, have 3" the moment
   the catchall header actually got included anywhere (see point 1's forwarding-chain fix).
   `int fn();` (empty parens, K&R-style) declares a function with no fixed parameter list at
   all, so clang accepts any call shape without complaint -- the only thing we actually want
   from a stub whose real signature we don't know.

3. Missing arch define ("Please check that X, Y or Z is defined!", from a codebase's own
   #error guard) -> the needed define is appended to config.iar_compat_defines *in memory*
   for the rest of this process (both this module's own detection rounds and the real
   analysis run that follows it use the same config object) -- never written to
   config.yaml. A tip is printed to add it permanently; otherwise every future run repeats
   the same detection rounds from scratch.

A handful of standard headers get real content instead of an empty include guard, because
an empty stub silently produces new, harder-to-diagnose errors downstream for headers whose
whole job is defining macros/keywords rather than just declaring functions -- `assert.h` is
the sharp example: without it, `static_assert` isn't recognised at all under the C standard
fwlens invokes clang with (no `-std=` flag is passed, so clang defaults to gnu17, where only
`_Static_assert` is a builtin keyword). But a header stub only helps translation units that
actually include that header -- if `static_assert` is used inside a header that itself never
includes `<assert.h>` (relying on the *real* IAR compiler treating it as an always-available
keyword, which clang doesn't), no stub fixes it for files that reach that header without
`<assert.h>` anywhere in their own chain. That specific gap needs
`static_assert=_Static_assert` in `iar_compat_defines` -- a global define, not a header fix
-- see the guide's Project-wide auto-stub section.
"""

from __future__ import annotations

import re
from pathlib import Path

from rich.console import Console

from fwlens.config import FwLensConfig, macro_name

_MAX_ROUNDS = 3

# Clang's own bundled headers -- never shadow these with a stub.
_NEVER_STUB = {
    "stdint.h", "stddef.h", "stdbool.h", "stdarg.h",
    "float.h", "limits.h", "iso646.h", "stdalign.h",
    "stdnoreturn.h", "stdatomic.h",
}

_CATCHALL_NAME = "_iar_builtins_stub.h"
_CATCHALL_GUARD = "_IAR_BUILTINS_STUB_H"

# Headers that need real content, not just an empty include guard, because code depends on
# a macro/keyword they define rather than just a function declaration. See module docstring
# for why assert.h specifically matters. Extend this if another header shows the same
# pattern (an empty stub clearing the "file not found" but new errors appearing right after).
_KNOWN_HEADER_STUBS = {
    "assert.h": (
        "#ifndef assert\n#define assert(x) ((void)0)\n#endif\n"
        "#ifndef static_assert\n#define static_assert _Static_assert\n#endif\n"
    ),
    "time.h": (
        "#ifndef _TIME_T_DEFINED\n#define _TIME_T_DEFINED\ntypedef long time_t;\n#endif\n"
    ),
    "errno.h": (
        "extern int errno;\n"
        "#define EDOM   33\n#define ERANGE 34\n"
    ),
}

# Correct signatures for well-known standard-library and CMSIS-intrinsic functions --
# a wrong-arity guess is worse than no stub at all once it's actually visible to real call
# sites (see module docstring point 2). Sourced from the C standard and ARM's CMSIS Core
# intrinsics reference; size_t/etc. come from the real stddef.h (in _NEVER_STUB, so it's
# never shadowed by a stub, and is always available to pull these types from).
_KNOWN_FUNCTION_SIGNATURES = {
    # <string.h>
    "memcpy": "void *memcpy(void *, const void *, size_t);",
    "memset": "void *memset(void *, int, size_t);",
    "memcmp": "int memcmp(const void *, const void *, size_t);",
    "memmove": "void *memmove(void *, const void *, size_t);",
    "strlen": "size_t strlen(const char *);",
    "strcpy": "char *strcpy(char *, const char *);",
    "strncpy": "char *strncpy(char *, const char *, size_t);",
    "strcmp": "int strcmp(const char *, const char *);",
    "strncmp": "int strncmp(const char *, const char *, size_t);",
    "strcat": "char *strcat(char *, const char *);",
    "strncat": "char *strncat(char *, const char *, size_t);",
    "strstr": "char *strstr(const char *, const char *);",
    "strchr": "char *strchr(const char *, int);",
    "strrchr": "char *strrchr(const char *, int);",
    "strtok": "char *strtok(char *, const char *);",
    "strnlen": "size_t strnlen(const char *, size_t);",
    "strcasecmp": "int strcasecmp(const char *, const char *);",
    "strncasecmp": "int strncasecmp(const char *, const char *, size_t);",
    # <stdlib.h>
    "malloc": "void *malloc(size_t);",
    "calloc": "void *calloc(size_t, size_t);",
    "realloc": "void *realloc(void *, size_t);",
    "free": "void free(void *);",
    "abs": "int abs(int);",
    "atoi": "int atoi(const char *);",
    "strtol": "long strtol(const char *, char **, int);",
    "strtoul": "unsigned long strtoul(const char *, char **, int);",
    "strtoll": "long long strtoll(const char *, char **, int);",
    "strtoull": "unsigned long long strtoull(const char *, char **, int);",
    # <stdio.h>
    "snprintf": "int snprintf(char *, size_t, const char *, ...);",
    "sprintf": "int sprintf(char *, const char *, ...);",
    # <ctype.h>
    "isdigit": "int isdigit(int);",
    "isxdigit": "int isxdigit(int);",
    "isalpha": "int isalpha(int);",
    "isspace": "int isspace(int);",
    "toupper": "int toupper(int);",
    "tolower": "int tolower(int);",
    # ARM CMSIS Core intrinsics -- <cmsis_iccarm.h> / IAR's intrinsics.h
    "__CLZ": "unsigned int __CLZ(unsigned int);",
    "__RBIT": "unsigned int __RBIT(unsigned int);",
    "__DSB": "void __DSB(void);",
    "__ISB": "void __ISB(void);",
    "__DMB": "void __DMB(void);",
    "__WFI": "void __WFI(void);",
    "__WFE": "void __WFE(void);",
    "__SEV": "void __SEV(void);",
    "__NOP": "void __NOP(void);",
    "__no_operation": "void __no_operation(void);",
    "__LDREX": "unsigned long __LDREX(unsigned long *);",
    "__STREX": "int __STREX(unsigned long, unsigned long *);",
    "__CLREX": "void __CLREX(void);",
    "__disable_interrupt": "void __disable_interrupt(void);",
    "__enable_interrupt": "void __enable_interrupt(void);",
    "__get_PRIMASK": "unsigned int __get_PRIMASK(void);",
    "__set_PRIMASK": "void __set_PRIMASK(unsigned int);",
    "__get_BASEPRI": "unsigned int __get_BASEPRI(void);",
    "__set_BASEPRI": "void __set_BASEPRI(unsigned int);",
}


def _generic_prototype(fn: str) -> str:
    """
    Old-style (K&R, unprototyped) declaration for a function whose real signature isn't
    known -- empty parens, not an explicit fixed-arity guess. Clang doesn't check argument
    count or types against a declaration with no parameter list, so any real call shape
    compiles; a guessed fixed-arity prototype (e.g. always 4 params) would instead reject
    real call sites that don't happen to match the guess, which is worse than not stubbing
    the function at all.
    """
    return f"int {fn}(); /* auto-stub, unknown signature -- unprototyped, accepts any call shape */"

_HDR_RE = re.compile(r"'([^']+\.h)' file not found")
_FN_RE = re.compile(r"call to undeclared (?:library )?function '([^']+)'")
_ARCH_ERR_RE = re.compile(r'"Please check that (.+) is defined!"')


def _ensure_catchall(stubs_dir: Path) -> None:
    catchall = stubs_dir / _CATCHALL_NAME
    if not catchall.exists():
        catchall.write_text(
            f"/* Auto-generated IAR builtin stubs for static analysis */\n"
            f"#ifndef {_CATCHALL_GUARD}\n#define {_CATCHALL_GUARD}\n#endif\n"
        )


def _write_header_stub(stubs_dir: Path, header: str, console: Console) -> None:
    stub_path = stubs_dir / header
    body = _KNOWN_HEADER_STUBS.get(header, "")

    if stub_path.exists():
        # Self-heal: a header that's on the curated list but was written before it got
        # curated content (or before a later addition to that content) stays stuck with
        # an empty/incomplete stub forever otherwise -- same class of bug as the function
        # catchall not repairing stale entries. Only rewrite if the expected body isn't
        # already present; leave anything else alone (may be hand-edited).
        if body and body not in stub_path.read_text():
            existing = stub_path.read_text()
            # Insert the missing body just after the include guard's #define line.
            lines = existing.splitlines(keepends=True)
            insert_at = next((i + 1 for i, l in enumerate(lines) if l.strip().startswith("#define")), 0)
            lines[insert_at:insert_at] = [body]
            stub_path.write_text("".join(lines))
            console.print(f"  [green]Fixed stale stub:[/green] iar_stubs/{header} (added missing content)")
        return

    guard = header.upper().replace(".", "_").replace("-", "_")
    # Every generated stub pulls in the shared catchall so undeclared-function prototypes
    # are visible regardless of which particular header a translation unit reaches first --
    # see module docstring for why a single forwarding header isn't reliable enough.
    include_line = "" if header == _CATCHALL_NAME else f'#include "{_CATCHALL_NAME}"\n'
    content = (
        f"/* Auto-generated {'functional' if body else 'empty'} stub for static analysis: {header} */\n"
        f"#ifndef _{guard}_STUB\n#define _{guard}_STUB\n"
        f"{body}{include_line}"
        f"#endif\n"
    )
    stub_path.write_text(content)
    kind = "functional" if body else "empty"
    console.print(f"  [green]Created {kind} stub:[/green] iar_stubs/{header}")


_DECL_LINE_FN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# Matches the specific broken pattern from an earlier version of this module (always
# 4 fixed unsigned-int parameters, regardless of the real function's arity) -- see
# _generic_prototype's docstring for why that's actively wrong, not just imprecise.
_OLD_WRONG_ARITY_RE = re.compile(
    r"^unsigned int \w+\(unsigned int, unsigned int, unsigned int, unsigned int\);"
)


def _parse_existing_decls(text: str) -> dict[str, str]:
    """function name -> its full existing declaration line, from a previously-written
    catchall header. Skips comments/preprocessor lines."""
    decls: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "/*", "*", "//")):
            continue
        m = _DECL_LINE_FN_RE.search(stripped)
        if m:
            decls[m.group(1)] = stripped
    return decls


def _write_function_stubs(stubs_dir: Path, functions: set[str], console: Console) -> bool:
    """
    Ensure every function in `functions` has a declaration in the catchall header, and
    self-heal any *existing* declaration that matches the known-broken old wrong-arity
    pattern -- rewriting the whole file from a parsed, deduplicated set of declarations
    each time, rather than only ever appending. A prior version of this module both wrote
    the wrong-arity pattern AND, once fixed to stop writing it, still skipped re-checking
    any function whose name merely already appeared somewhere in the file -- so an
    `iar_stubs/` directory populated by that earlier version stayed permanently stuck with
    the broken declarations even after the bug was fixed, since nothing ever went back to
    repair them. This rebuild pass is what actually fixes that: it runs on every call, not
    just when a stub is first created. Returns True if anything changed.
    """
    catchall = stubs_dir / _CATCHALL_NAME
    _ensure_catchall(stubs_dir)
    existing_text = catchall.read_text()
    existing_decls = _parse_existing_decls(existing_text)

    # Self-heal stub files written before the stddef.h include was added below --
    # without it, size_t-using declarations (malloc, memcpy, ...) fail to parse
    # with confusing "parameter list without types" / "implicit int" errors that
    # look nothing like a missing-include problem.
    needs_stddef_fix = "#include <stddef.h>" not in existing_text

    all_fns = set(existing_decls) | set(functions)
    if not all_fns and not needs_stddef_fix:
        return False

    final_decls: dict[str, str] = {}
    changed = needs_stddef_fix
    if needs_stddef_fix:
        console.print(f"  [green]Fixed stale stub:[/green] {_CATCHALL_NAME} was missing "
                       f"#include <stddef.h> -- size_t-using declarations couldn't parse")
    for fn in sorted(all_fns):
        correct = _KNOWN_FUNCTION_SIGNATURES.get(fn)
        prior = existing_decls.get(fn)
        if correct is not None:
            final_decls[fn] = correct
            if prior != correct:
                changed = True
                verb = "Fixed stale stub for" if prior else "Stubbed"
                console.print(f"  [green]{verb} function:[/green] {fn}(...)  [dim](known signature)[/dim]")
        elif prior and not _OLD_WRONG_ARITY_RE.match(prior):
            # Some other declaration already there (not the known-broken pattern) --
            # leave it alone; it may be hand-edited or from a source we don't recognise.
            final_decls[fn] = prior
        else:
            new_decl = _generic_prototype(fn)
            final_decls[fn] = new_decl
            if prior != new_decl:
                changed = True
                verb = "Fixed stale stub for" if prior else "Stubbed"
                console.print(f"  [green]{verb} function:[/green] {fn}(...)  [dim](unprototyped)[/dim]")

    if not changed:
        return False

    body = (f"/* Auto-generated IAR builtin stubs for static analysis */\n"
            f"#ifndef {_CATCHALL_GUARD}\n#define {_CATCHALL_GUARD}\n"
            f"#include <stddef.h>  /* size_t, NULL -- must come before the declarations below;\n"
            f"                        never shadowed since stddef.h is in _NEVER_STUB */\n")
    for fn in sorted(final_decls):
        body += final_decls[fn] + "\n"
    body += f"#endif /* {_CATCHALL_GUARD} */\n"
    catchall.write_text(body)
    return True


def _apply_arch_defines(config: FwLensConfig, arch_needed: set[str], stubs_dir: Path, console: Console) -> bool:
    """
    Add missing arch defines two ways: appended to config.iar_compat_defines in memory
    (visible to anything in *this* process reading it directly), and written to
    iar_stubs/_auto_detected_defines.txt (visible to the parse subprocess workers, which
    only receive a config *path* and independently call load_config() fresh -- see the
    comment in fwlens.config.load_config for why the in-memory mutation alone does
    nothing for them). Neither is ever written to config.yaml itself. Returns True if
    anything new was added.

    Defines EVERY candidate macro named in the message, not just one guessed as "most
    likely" -- these messages are virtually always the fallback branch of an
    #if defined(A) || defined(B) || ... / #error chain (a codebase asking "is this at
    least one of these architectures"), so defining several of them can't make that
    check any less true, only a genuinely mutually-exclusive #elif chain would resolve
    to whichever candidate the header itself checks first, not whichever we listed
    first. A single best-guess candidate previously left this permanently unresolved
    whenever the guess was wrong, with no way to tell short of reading the header by
    hand; defining the whole set removes the guessing entirely.

    Candidates are separated by "," for every item but the last, which is instead
    joined to the second-to-last with " or " or " and " (English list conventions,
    e.g. "A, B, C or D") -- splitting on comma alone leaves that last pair stuck
    together as one malformed token.
    """
    existing = set(config.iar_compat_defines)
    existing_names = {macro_name(d) for d in config.iar_compat_defines}
    added = []
    for needed_str in arch_needed:
        # Split on commas first, then split the final combined pair on " or "/" and ".
        raw_candidates = [s.strip() for s in needed_str.split(",")]
        if raw_candidates:
            last = raw_candidates[-1]
            for sep in (" or ", " and "):
                if sep in last:
                    raw_candidates[-1:] = [p.strip() for p in last.split(sep)]
                    break

        for choice in raw_candidates:
            choice = choice.strip("_").strip()
            if not choice or not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", choice):
                continue  # not a clean identifier -- skip rather than emit a bad -D
            define = f"__{choice}__=1"
            name = macro_name(define)
            if name in existing_names:
                continue  # config.yaml already sets this macro (possibly to a
                          # different value than our "=1" guess, e.g. a value
                          # compared against __CORE__) -- never shadow it
            if define not in existing:
                config.iar_compat_defines.append(define)
                existing.add(define)
                existing_names.add(name)
                added.append(define)
    if added:
        side_channel = stubs_dir / "_auto_detected_defines.txt"
        prior = side_channel.read_text().splitlines() if side_channel.exists() else []
        side_channel.write_text("\n".join(prior + added) + "\n")
        console.print(f"  [yellow]Added arch define (written to iar_stubs/_auto_detected_defines.txt):"
                      f"[/yellow] {', '.join(added)}")
        console.print(f"  [yellow]Tip:[/yellow] add {', '.join(added)} to iar_compat_defines "
                      f"in config.yaml to make it permanent and skip this file entirely.")
    return bool(added)


def run_auto_stub(config: FwLensConfig, console: Console) -> bool:
    """
    Parse the whole in-scope file set, fix every missing header / undeclared function /
    missing arch define found across ALL of it (not just one file), and repeat until a
    round finds nothing new to fix (or _MAX_ROUNDS is hit). Returns True if anything was
    created or changed. Only meaningful in EWP mode -- directory mode has no
    $TOOLKIT_DIR$ headers to stub around in the first place, so callers should skip this
    when config.project.mode == "directory".

    Each round does a full parallel parse (fwlens.parser.pipeline.run_pipeline) purely to
    read back parse_diagnostics -- this is not cheap for a large project, which is why
    _MAX_ROUNDS is small. A project still finding new problems after 3 rounds likely has
    something an empty/generic stub can't paper over; `debug-parse --file <name>` on a
    specific remaining failure is the better next step at that point.
    """
    from fwlens.parser.pipeline import run_pipeline

    stubs_dir = config.config_path.parent / "iar_stubs"
    stubs_dir.mkdir(exist_ok=True)
    # Create the catchall before round 1 even parses, not after it's discovered missing.
    # Every generated header stub #includes it unconditionally (point 1 in the module
    # docstring), so if it doesn't exist yet, round 2's parse hits "_iar_builtins_stub.h
    # file not found" as a *new* problem and it gets created via the generic header-stub
    # path instead -- burning a whole round before any real undeclared-function detection
    # can even start, and (until the exclusion below) risking two different code paths
    # racing to create the same file with different guard tokens.
    _ensure_catchall(stubs_dir)
    # Proactively heal any already-existing curated header stub before round 1 even
    # parses, not only when a "file not found" diagnostic names it -- a header that
    # already exists (from a run predating a later addition to _KNOWN_HEADER_STUBS, e.g.
    # time.h getting a time_t typedef added after the empty stub was already written)
    # never produces that diagnostic again once it exists, so it would otherwise never
    # get re-checked at all.
    for known_header in _KNOWN_HEADER_STUBS:
        if (stubs_dir / known_header).exists():
            _write_header_stub(stubs_dir, known_header, console)
    any_created = False
    # Diagnostic message -> count from the previous round, so each round's summary can
    # show whether specific problems are actually shrinking or just being re-detected and
    # silently ignored -- see the "already fixed but still occurring" check below.
    prev_counts: dict[str, int] = {}
    last_arch_needed: set[str] = set()
    last_total_diags = 0

    for round_num in range(1, _MAX_ROUNDS + 1):
        console.print(f"[cyan][fwlens][/cyan] Auto-stub round {round_num}/{_MAX_ROUNDS}: parsing...")
        model = run_pipeline(config)

        headers: set[str] = set()
        functions: set[str] = set()
        arch_needed: set[str] = set()
        counts: dict[str, int] = {}
        for m in model.modules:
            for diag in m.parse_diagnostics:
                msg = diag.get("message", "")
                counts[msg] = counts.get(msg, 0) + 1
                m_hdr = _HDR_RE.search(msg)
                m_fn = _FN_RE.search(msg)
                m_arch = _ARCH_ERR_RE.search(msg)
                if m_hdr and m_hdr.group(1) not in _NEVER_STUB:
                    headers.add(m_hdr.group(1))
                elif m_fn:
                    functions.add(m_fn.group(1))
                elif m_arch:
                    arch_needed.add(m_arch.group(1))

        total_diags = sum(counts.values())
        console.print(f"  [dim]{total_diags} diagnostic(s) this round -- "
                      f"{len(headers)} distinct missing header(s), "
                      f"{len(functions)} distinct undeclared function(s), "
                      f"{len(arch_needed)} distinct arch-define message(s)[/dim]")

        # Explicit-name detection for a pattern this code otherwise can't auto-fix (no
        # #error, no missing-header, no undeclared-function shape to hook -- it's a raw
        # parse failure from `static_assert` being used without `<assert.h>` in scope,
        # see the assert.h note further down). "type specifier missing, defaults to
        # int" this often is close to always this exact cascade, not a real int-default
        # problem in the code -- called out by name here because a prose explanation of
        # the same thing was apparently easy to miss across several runs of this tool.
        implicit_int_count = sum(c for m, c in counts.items()
                                  if "type specifier missing" in m and "implicit int" in m)
        if implicit_int_count > 20:
            console.print(
                f"  [bold red]Likely cause found:[/bold red] {implicit_int_count} "
                f"\"type specifier missing... implicit int\" diagnostic(s) this round -- "
                f"this volume is the signature of `static_assert` being used without "
                f"`<assert.h>` in scope, not real implicit-int code. Fix: add this exact "
                f"line to iar_compat_defines in YOUR config.yaml (the actual file "
                f"Run-FwLens.ps1 loads -- not config.example.yaml):\n"
                f'      - "static_assert=_Static_assert"\n'
                f"  This is not something --auto-stub can add automatically (there's no "
                f"missing-header or #error diagnostic to detect, only this raw parse "
                f"failure) -- it has to go in your config.yaml directly."
            )

        new_headers = {h for h in headers if h != _CATCHALL_NAME and not (stubs_dir / h).exists()}

        stubs_dir.mkdir(exist_ok=True)
        arch_changed = _apply_arch_defines(config, arch_needed, stubs_dir, console) if arch_needed else False

        # A message that's STILL appearing, in the same or growing count, despite a fix
        # already being on record for it (arch_needed non-empty but arch_changed False --
        # meaning every arch define it named was already added in an earlier round) means
        # the fix isn't actually taking effect, not that there's nothing left to do. This
        # is exactly the gap that previously let the loop silently declare "nothing new to
        # fix" while the same 126 arch-define errors kept showing up in the final report:
        # arch_needed being non-empty was never checked on its own, only whether adding a
        # define this round was "new" -- since it wasn't (round 1 already added it), the
        # loop stopped without ever surfacing that the diagnostic was still there.
        if arch_needed and not arch_changed:
            for msg in arch_needed:
                full_msg = next((k for k in counts if msg in k), msg)
                console.print(
                    f"  [red]Warning:[/red] every candidate macro named in this message "
                    f"is already defined (all of them, not just a guessed one -- see the "
                    f"guide) but the diagnostic is still occurring "
                    f"({counts.get(full_msg, '?')}x this round, "
                    f"{prev_counts.get(full_msg, '?')}x last round). This means the "
                    f"header's real #if condition isn't simply \"is one of these defined\" "
                    f"-- it likely checks a specific value, a different macro entirely, or "
                    f"the message is generic boilerplate not tied to the actual check. "
                    f"Run `debug-parse --file <one affected file>` and read the header the "
                    f"#error actually comes from -- guessing further from the message text "
                    f"alone won't resolve this."
                )

        # functions is the FULL set still reported as undeclared this round, not just
        # names never seen before -- _write_function_stubs needs to see all of them so it
        # can detect and repair a stale declaration for a name it already stubbed in an
        # earlier (possibly much earlier, pre-bugfix) run, not just skip past it because
        # the name already appears somewhere in the file.
        functions_fixed = _write_function_stubs(stubs_dir, functions, console)

        if not new_headers and not functions_fixed and not arch_needed:
            console.print(f"[cyan][fwlens][/cyan] Auto-stub: nothing new to fix "
                          f"after round {round_num} -- stopping.")
            break

        for h in sorted(new_headers):
            _write_header_stub(stubs_dir, h, console)
        if new_headers or functions_fixed or arch_changed:
            any_created = True
        prev_counts = counts
        last_arch_needed = arch_needed
        last_total_diags = total_diags

    if last_arch_needed:
        console.print(
            f"[yellow][fwlens][/yellow] {len(last_arch_needed)} arch-define message(s) "
            f"still unresolved after auto-stub finished ({last_total_diags} total "
            f"diagnostics in the last round). The real analysis run below will still show "
            f"these -- see the warning(s) above for which define(s) were tried and didn't "
            f"clear it. This usually means the specific header checks a different macro "
            f"or value than the one this code guessed; check the include chain manually "
            f"with `debug-parse --file <one affected file>`."
        )

    return any_created

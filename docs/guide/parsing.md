# Parsing, stubs and diagnostics

[Back to the guide contents](../../FWLENS_GUIDE.md)

## Two-hash comparison

`diff-breach` compares breaches between two `fwlens_results.json` exports -- typically one
captured at each of two git hashes -- without touching your working tree itself. You check
out and export each side; fwlens just diffs the two files:

```powershell
git checkout main
.\Run-FwLens.ps1 export --config config.yaml
Copy-Item output\exports\fwlens_results.json main.json

git checkout feature-branch
.\Run-FwLens.ps1 export --config config.yaml
.\Run-FwLens.ps1 diff-breach --from-json main.json --to-json output\exports\fwlens_results.json --fail-on-breach
```

Like `analyze`/`report`'s baseline check, only breaches that are new or worse in
`--to-json` relative to `--from-json` are reported; a breach present at the same severity
on both sides is silent. Thresholds come from `--config`'s `config.yaml`, not from whichever
config produced either JSON file, so both sides are judged against the same bar even if the
two commits' configs differed. This reports breach status only (crossed-threshold-or-not) --
it won't show a function that moved from CC 8 to CC 14 while staying under a CC 15
threshold; for that you'd need to diff the raw metric values in the two JSON files directly.

---

## Project-wide auto-stub

`debug-parse` auto-fixes missing-header, undeclared-function, and missing-arch-define
errors, but only for one file per run -- fine for diagnosing a single failure, tedious for
clearing every stub a whole project needs before its first clean `analyze`/`report`.
`--auto-stub` generalises the same mechanism project-wide:

```powershell
.\Run-FwLens.ps1 report --auto-stub
```

Before the real parse, it parses the whole in-scope file set, aggregates every
missing-header, undeclared-function, and missing-arch-define diagnostic across *all*
modules (not just one), fixes them, writes stubs to `iar_stubs\` (same directory
`debug-parse` uses, resolved next to `config.yaml`), and repeats -- up to 3 rounds -- until
a round finds nothing new to fix. Each round is printed to the console (what got created or
added, why the loop stopped), so nothing changes silently.

EWP mode only -- directory mode has no `$TOOLKIT_DIR$` headers to stub around, so
`--auto-stub` is a no-op there (with a console note) rather than an error.

Three diagnostic shapes are handled:

- **Missing header** (`'X.h' file not found`) -- stubbed. Most get an empty include-guard
  stub, enough when the only thing needed from that header is a function declaration
  (covered separately by the undeclared-function catch-all below). A small curated list of
  headers get real content instead, because code depends on a *macro or keyword* they
  define rather than just a function -- see the assert.h note below. Every generated stub,
  functional or empty, also `#include`s a shared catch-all header
  (`iar_stubs\_iar_builtins_stub.h`) so that whichever header a translation unit reaches
  first still pulls in every undeclared-function prototype discovered so far -- an earlier
  version tried wiring that catch-all in through a single forwarding header (mimicking
  IAR's own `intrinsics.h` -> `iccarm_builtin.h` chain), which only works if the *real*
  `intrinsics.h` exists to do the forwarding; once it's itself a stub, that chain goes
  nowhere and every intrinsic looks undeclared regardless of the catch-all having the
  right prototypes. The catch-all itself is created (empty, correctly guarded) before the
  first parse even runs, not on demand -- creating it lazily meant the very first round
  that referenced it from another stub hit its own "file not found", burning a whole
  extra round before real undeclared-function detection could start.
- **Undeclared function** (`call to undeclared function 'X'`) -- a prototype gets appended
  to the catch-all. A small curated list of well-known standard-library and CMSIS-intrinsic
  functions (`memcpy`, `strlen`, `__DSB`, `__CLZ`, ...) get their real signature; anything
  else gets an old-style, unprototyped declaration (`int fn();`) rather than a guessed
  fixed-arity one. A guessed prototype is worse than none: clang treats a *wrong*
  prototype as authoritative once it's visible, so a fixed 4-parameter guess made a real
  3-argument `memcpy(dest, src, n)` call site fail with "too few arguments, expected 4,
  have 3" the moment the catch-all actually got included anywhere (which it didn't,
  before the forwarding-chain fix above -- so this was invisible until that got fixed,
  then broke over a thousand call sites in one project). `int fn();` has no fixed
  parameter list at all, so clang accepts any call shape without complaint.
- **Missing arch define** (a codebase's own `#error "Please check that ... is defined!"`
  guard) -- the needed define is written to `iar_stubs\_auto_detected_defines.txt` and
  read back by `fwlens.config.load_config` on every subsequent load, in *any* process
  (never written to `config.yaml` itself), with a console tip to add it permanently so
  future runs don't repeat the same detection rounds. It has to go through a file rather
  than an in-memory config mutation: parsing runs in subprocess workers that only receive
  a config *path*, not the live Python object, and independently reload `config.yaml`
  fresh in each subprocess -- an in-memory-only mutation in the main process would be
  invisible to them (an earlier version of this feature had exactly that bug: the console
  correctly reported the define as "added", but the actual parse workers never saw it,
  since they'd already reloaded a config that never changed on disk).

  When the `#error` lists several candidate macros (e.g. `__ARM6M__, __ARM7M__,
  __ARM7EM__, __ARM8M_BASELINE__, __ARM8M_MAINLINE__ or __ARM8EM_MAINLINE__`), fwlens
  defines *every* candidate named, not just one guessed as most likely. These messages
  are almost always the fallback branch of an `#if defined(A) || defined(B) || ... /
  #error` chain, so defining several of them can't make that condition any less true --
  only a genuinely mutually-exclusive `#elif` chain would end up resolving to whichever
  candidate the header itself checks first, not whichever fwlens listed first. An
  earlier version picked a single "most likely" candidate (preferring `ARM7EM` over
  `ARM7M` for a Cortex-M4F target) and left the problem permanently unresolved whenever
  that guess was wrong, with no way to tell short of reading the header by hand.
  Candidates are comma-separated except the last, which is joined to the previous one
  with " or "/" and " (English list conventions) -- splitting on comma alone leaves that
  last pair stuck together as one malformed token, so that join is handled separately.

  If a persisting arch-define warning still appears after every named candidate has been
  defined, that's a strong signal the header's real condition isn't "is one of these
  defined" at all -- it likely checks a specific value, an entirely different macro, or
  the message text is generic boilerplate not tied to the actual `#if`. At that point
  `debug-parse --file <name>` on a specific affected file, then reading the header the
  `#error` actually comes from, is the only way forward -- guessing further from the
  message text alone won't resolve it.

**Every round prints its diagnostic counts** (total, plus how many distinct missing
headers / undeclared functions / arch-define messages), not just what changed -- this is
what makes it possible to tell "genuinely nothing left to fix" apart from "found the same
problem again but didn't recognise it as new." If a round finds an arch-define message
that already has a define on record from an earlier round, but the diagnostic is still
occurring, that's printed as an explicit warning rather than silently treated as
converged -- an earlier version of this loop only checked whether a round added something
*new*, so a persisting diagnostic whose fix had already been recorded (but wasn't actually
taking effect) caused the loop to declare "nothing new to fix" and stop, while the same
diagnostic kept showing up in the final report. If you see that warning, the define this
code guessed usually isn't the one the specific header actually checks -- `debug-parse
--file <one affected file>` on a representative file, then reading the header the `#error`
actually comes from, is the fastest way to find the real one.

**Stale stubs from a previous version of this feature are actively repaired, not just
left alone.** Every run rewrites the whole catchall header from a freshly parsed set of
existing declarations, replacing anything matching the specific broken pattern an earlier
version of this code used to write (a guessed fixed 4-parameter signature for every
unknown function, regardless of its real arity) with either the correct signature (for
the curated well-known functions) or a safe unprototyped one. Skipping repair for a name
that "already appears somewhere in the file" was itself a bug in an earlier version: it
meant a bug fix to the *generator* never reached stubs already sitting on disk from before
the fix existed, so `iar_stubs\` populated by an older fwlens kept regenerating the same
broken content on every subsequent run, no matter how many times the underlying code got
fixed. If you're upgrading from a version predating this, one run should self-heal
everything already in `iar_stubs\` -- deleting the directory first isn't required, but is
a reasonable "start clean" option if you want to confirm there's no other leftover cruft.

> **Important -- `assert.h`:** fwlens doesn't pass a `-std=` flag, so clang defaults to
> gnu17, where `_Static_assert` is a builtin keyword but lowercase `static_assert` only
> exists as a macro from `<assert.h>`. An empty stub clears the "file not found" fatal but
> leaves any `static_assert(...)` line unparseable, cascading into corrupted parsing of
> everything after it in that header -- so `assert.h`'s stub gets real content
> (`#define assert(x) ((void)0)` / `#define static_assert _Static_assert`) instead of an
> empty guard. That only helps translation units that actually `#include <assert.h>`
> themselves, though -- if a *header* uses `static_assert` without including `<assert.h>`
> itself (relying on the real IAR compiler treating it as an always-available keyword,
> which clang doesn't), no header stub fixes it for files that reach that header without
> `<assert.h>` anywhere in their own chain. That needs a global fix instead:
> `static_assert=_Static_assert` in `iar_compat_defines` (already in
> `config.example.yaml`'s default list, but has to be copied into your own `config.yaml`
> -- `--auto-stub` can't add this one for you automatically the way it does arch defines,
> since the failure is a raw parse error with no `#error` directive to detect) makes it
> available everywhere regardless of which translation unit includes what.

**`time.h`** gets the same treatment for the same reason: an empty stub clears "file not
found" but leaves `time_t` undefined for any code that uses it, so it gets a minimal
`typedef long time_t;` instead. Curated function signatures beyond the standard set noted
above also include `__LDREX`/`__STREX` (IAR's raw compiler intrinsics declare these with
`unsigned long *`, not `unsigned int *` -- a mismatch here doesn't fail loudly like a
missing prototype does, it just produces "incompatible pointer types" at every real call
site) and a handful of `<string.h>` functions clang has its own builtin awareness of
(`strtok`, `strnlen`, `strcasecmp`, `strncasecmp`) that need a real signature for the same
reason `memcpy` does -- an unprototyped fallback for a function clang already knows about
still triggers a warning, just a different one ("incompatible redeclaration" or "without
a prototype is deprecated") than a wrong-arity guess would.

**Every parse also runs with `-fno-builtin`**, not just the ones through `--auto-stub`.
Without it, clang treats well-known library function names as builtins with their own
hardcoded signature baked into the compiler, entirely independent of whatever prototype a
stub provides -- so even a textbook-correct curated signature can still be reported as an
"incompatible redeclaration" if it doesn't match clang's *internal* one exactly for this
specific target (down to the precise spelling of a size/type parameter). `-fno-builtin`
disables that recognition, making our own stub declarations authoritative regardless.
This eliminates the whole class of problem at the source rather than chasing individual
mismatched signatures one at a time.

**The console summary also runs two of these detectors on every `analyze`/`report`/
`export`, not only when `--auto-stub` is used.** A high volume of "type specifier
missing... implicit int" is called out by name as the `static_assert`-without-`assert.h`
signature (since that fix has to go in your own `config.yaml` and there's no diagnostic
shape for fwlens to detect and patch automatically), and a persisting "Please check that
... is defined!" volume gets the same explicit callout pointing at `--auto-stub` and, if
that's already been tried, `debug-parse`. Both print directly under the Parse Diagnostics
table rather than only in `--auto-stub`'s own round-by-round output, since a real cause
buried in prose across several tool responses is easy to miss -- the tool should say it
plainly in the one place everyone actually looks first.

**Already-existing stubs get checked against the curated lists on every run, not just new
ones.** A header or function stub written before a later addition to `_KNOWN_HEADER_STUBS`
or `_KNOWN_FUNCTION_SIGNATURES` (e.g. `time.h` before the `time_t` typedef was added, or
`__LDREX` before its parameter type was corrected) doesn't get silently left behind --
every curated header already on disk is checked at the start of each `--auto-stub` run,
and every function still showing up as undeclared gets checked against the current
signature regardless of whether it's a brand-new name. Upgrading fwlens and re-running
`--auto-stub` is enough to pick up improvements to these lists; deleting `iar_stubs\`
first is never required, only ever a "start clean" option.

If you hit the same empty-stub-then-new-error shape with a different header, it needs the
same treatment as `assert.h` -- add it to `_KNOWN_HEADER_STUBS` in `fwlens/autostub.py`.

Each round does a full parallel parse purely to re-read diagnostics, so this isn't free on
a large project -- that's why it's capped at 3 rounds and opt-in rather than automatic. A
project still finding new missing headers after 3 rounds likely has something an empty or
generic stub can't paper over (commonly: a header gated behind a `#define` not yet in
`iar_compat_defines`) -- `debug-parse --file <name>` on a specific remaining failure is the
better next step at that point.

---

## Diagnostic clusters

When many unrelated files hit the exact same parse diagnostic at the exact same line
number, that's not N independent problems -- it's one shared root cause (a missing
compiler-compat define, a broken header, an unresolved macro) whose parse-failure recovery
point happens to land at the same spot in every affected file. The diagnostic text itself
rarely names the real cause, only where the parser gave up and resynchronised -- "unknown
type name 'FI_NUM_FILES'" doesn't mention `static_assert` anywhere, even though that's
what's actually broken three lines earlier.

fwlens groups diagnostics by (message shape, **the file the diagnostic actually occurred
in**, line number) -- not just line number. libclang tracks the true physical location of
every diagnostic precisely, including inside an `#include`d header, and the file a
diagnostic is *reported against* (the `.c` translation unit fwlens was parsing) is very
often not the file it actually happened in at all. A shared header pulled in by dozens of
otherwise-unrelated `.c` files is exactly the shape a real cascading cause takes: same
message, same line, but only because every affected file reads the same header's same
broken line, not because of anything in the `.c` files' own content. Grouping by line
number alone risks two different failures: merging genuinely unrelated diagnostics whose
`.c` files coincidentally share a line number in their own code, and -- worse -- reading
and displaying the wrong source entirely, since a `.c` file's own line 158 has nothing to
do with a header's line 158. Quoted identifiers in the message are collapsed so "unknown
type name 'FOO'" and "unknown type name 'BAR'" still count as the same pattern, and any
pattern shared across 5+ distinct translation units gets pulled out as a cluster, sorted
by file count descending. For each cluster, fwlens reads the actual source around that
line from wherever it truly occurred and shows it directly -- turning "108 files hit this"
into "108 files hit this, and here's the header it's really in" without needing to export
a CSV, grep it, and paste a section back to figure out why.

Surfaced in the console summary (top 5 clusters, with `+/-3` lines of source context, and
an explicit `in header: ...` line whenever the real location differs from the `.c` file it
was reported against) and the `diagnostic_clusters` key in the JSON export (every cluster,
full context, `sample_tu` and `sample_file` both included so it's unambiguous which is
which). `parse_diagnostics.csv` carries the same distinction as two separate columns:
`file` (the translation unit) and `in_file` (where it actually happened, blank only in the
rare case libclang couldn't resolve a location at all) -- `line` is always relative to
`in_file`, not `file`, whenever the two differ. Two patterns get their own named detector
on top of this general mechanism, since they're common enough on IAR/embedded codebases to
call out explicitly rather than rely on the person reading a source snippet: `static_assert`
used without `<assert.h>` in scope (see the assert.h note under
[Project-wide auto-stub](#project-wide-auto-stub)), and a persisting arch-define `#error`
after `--auto-stub` has already tried every candidate macro the message names.


"""
Whole-project checks: identifier uniqueness and linkage (MISRA C:2012 2.3, 2.4, 2.8, 5.1 and 5.5
to 5.9, 8.3, 8.5 to 8.7).

While each translation unit is walked, ``collect_visit`` and ``collect_unit`` record the
file-scope declarations of first-party files and every reference to them. The system checks then
read those records once all translation units are done. They only see first-party translation
units: code in SDK or third-party directories is not analysed, so a function used only from there
looks unused, which is why the rules that depend on it are marked partial.
"""

from __future__ import annotations

import re
from pathlib import Path

from fwlens.standards.astutil import kids, kind_name
from fwlens.standards.engines import system_check
from fwlens.standards.sourcechecks import SourceFile

_TAG_KINDS = {"STRUCT_DECL": "struct", "UNION_DECL": "union", "ENUM_DECL": "enum"}
_DEFINE = re.compile(r"[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)")


def _loc(cursor) -> tuple:
    loc = cursor.location
    return (loc.file.name if loc.file else "", loc.line)


def entity_key(cursor) -> tuple:
    """Identity of a declared entity across translation units."""
    usr = cursor.get_usr()
    return ("usr", usr) if usr else ("loc", cursor.spelling, *_loc(cursor))


def _real_tag(cursor) -> bool:
    usr = cursor.get_usr()
    return bool(cursor.spelling) and bool(re.match(r"c:(?:[^@]*)@[SUE]@", usr))


# --- collection ------------------------------------------------------------------------------------------------

def collect_visit(ctx, cursor, kind) -> None:
    if kind in (ctx.K.DECL_REF_EXPR, ctx.K.TYPE_REF):
        ref = cursor.referenced
        if ref is not None:
            ctx.records.add_ref(entity_key(ref), ctx.main)


def _declaration_records(ctx, cursor) -> list[dict]:
    kind = kind_name(cursor)
    file, line = _loc(cursor)
    base = {"file": file, "line": line, "name": cursor.spelling, "tu": ctx.main}
    if kind in ("FUNCTION_DECL", "VAR_DECL"):
        params = []
        if kind == "FUNCTION_DECL":
            params = [(p.spelling, p.type.get_canonical().spelling) for p in cursor.get_arguments()]
        return [{**base, "what": "func" if kind == "FUNCTION_DECL" else "var", "usr": cursor.get_usr(),
                 "linkage": cursor.linkage.name, "defn": cursor.is_definition(), "params": params,
                 "const": cursor.type.is_const_qualified()}]
    if kind == "TYPEDEF_DECL":
        under = cursor.underlying_typedef_type.get_canonical().get_declaration()
        return [{**base, "what": "typedef", "key": entity_key(cursor),
                 "of_tag": under.spelling if under is not None and _real_tag(under) else ""}]
    if kind in _TAG_KINDS and _real_tag(cursor):
        out = [{**base, "what": "tag", "key": entity_key(cursor), "usr": cursor.get_usr()}]
        if kind == "ENUM_DECL":
            out += [{"file": file, "line": c.location.line, "name": c.spelling, "tu": ctx.main, "what": "enumconst"}
                    for c in kids(cursor) if kind_name(c) == "ENUM_CONSTANT_DECL"]
        return out
    if kind == "ENUM_DECL":
        return [{"file": file, "line": c.location.line, "name": c.spelling, "tu": ctx.main, "what": "enumconst"}
                for c in kids(cursor) if kind_name(c) == "ENUM_CONSTANT_DECL"]
    return []


def collect_unit(ctx) -> None:
    """After a translation unit's walk: its file-scope declarations, header references and macros."""
    records = ctx.records
    for c in ctx.top_level:
        f = c.location.file
        if f is None or f.name not in ctx.first_party:
            continue
        records.extend(_declaration_records(ctx, c))
        if f.name != ctx.main:
            for node in c.walk_preorder():                    # the walk skipped these header declarations
                nk = kind_name(node)
                if nk in ("DECL_REF_EXPR", "TYPE_REF") and node.referenced is not None:
                    records.add_ref(entity_key(node.referenced), ctx.main)
    for path in ctx.first_party:
        if path in records.macro_files:
            continue
        records.macro_files.add(path)
        sf = SourceFile.read(Path(path))
        if sf is None:
            continue
        for line_no, name, rest in sf.directives("code"):
            if name == "define":
                m = re.match(r"([A-Za-z_]\w*)", rest)
                if m:
                    records.append({"what": "macro", "name": m.group(1), "file": path, "line": line_no, "tu": ""})


# --- helpers ----------------------------------------------------------------------------------------------------

def _unique(records, *whats):
    seen = set()
    for r in records:
        if r["what"] in whats and (r["what"], r["name"], r["file"], r["line"]) not in seen:
            seen.add((r["what"], r["name"], r["file"], r["line"]))
            yield r


def _text(r) -> str:
    try:
        with open(r["file"], encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        return lines[r["line"] - 1].strip() if 0 < r["line"] <= len(lines) else ""
    except OSError:
        return ""


def _hit(r, function=None):
    return r["file"], r["line"], _text(r), function


def _entities(records):
    """Functions and variables at file scope grouped by identity."""
    groups: dict[str, list[dict]] = {}
    for r in _unique(records, "func", "var"):
        groups.setdefault(r["usr"], []).append(r)
    return groups


# --- 5.1 to 5.9: identifiers ------------------------------------------------------------------------------------

@system_check("external_identifiers_distinct")
def external_identifiers_distinct(records, params):
    limit = int(params.get("limit", 31))
    seen: dict[str, dict] = {}
    for r in sorted(_unique(records, "func", "var"), key=lambda r: (r["file"], r["line"])):
        if r["linkage"] != "EXTERNAL" or len(r["name"]) <= limit:
            continue
        head = r["name"][:limit]
        if head in seen and seen[head]["name"] != r["name"]:
            yield _hit(r)
        seen.setdefault(head, r)


def _identifier_records(records):
    return [r for r in _unique(records, "func", "var", "typedef", "tag", "enumconst")]


@system_check("identifier_matches_macro")
def identifier_matches_macro(records, params):
    macros = {r["name"] for r in _unique(records, "macro")}
    for r in _identifier_records(records):
        if r["name"] in macros:
            yield _hit(r)


@system_check("typedef_unique")
def typedef_unique(records, params):
    others: dict[str, list[dict]] = {}
    for r in _identifier_records(records):
        others.setdefault(r["name"], []).append(r)
    for r in _unique(records, "typedef"):
        clashes = [o for o in others[r["name"]] if o is not r and not (
            o["what"] == "tag" and r["of_tag"] == o["name"])]
        if clashes:
            yield _hit(r)


@system_check("tag_unique")
def tag_unique(records, params):
    by_name: dict[str, list[dict]] = {}
    for r in _unique(records, "tag"):
        by_name.setdefault(r["name"], []).append(r)
    typedefs = {r["name"]: r for r in _unique(records, "typedef")}
    for name, tags in by_name.items():
        distinct = {t["usr"] for t in tags}
        td = typedefs.get(name)
        if len(distinct) > 1:
            for t in tags[1:]:
                yield _hit(t)
        elif td is not None and td["of_tag"] != name:
            yield _hit(tags[0])


def _same_name_other_entity(records, linkage_wanted: set[str]):
    ents = _entities(records)
    names: dict[str, set] = {}
    for r in _identifier_records(records):
        key = r["usr"] if r["what"] in ("func", "var") else (r["what"], r["file"], r["line"])
        names.setdefault(r["name"], set()).add(key)
    for usr, decls in ents.items():
        first = sorted(decls, key=lambda d: (not d["defn"], d["file"], d["line"]))[0]
        if first["linkage"] in linkage_wanted and len(names.get(first["name"], ())) > 1:
            yield first


@system_check("external_identifier_unique")
def external_identifier_unique(records, params):
    for r in _same_name_other_entity(records, {"EXTERNAL"}):
        yield _hit(r)


@system_check("internal_identifier_unique")
def internal_identifier_unique(records, params):
    for r in _same_name_other_entity(records, {"INTERNAL"}):
        yield _hit(r)


# --- 8.3, 8.5, 8.6, 8.7: declarations across files ----------------------------------------------------------------

@system_check("declarations_agree")
def declarations_agree(records, params):
    for usr, decls in _entities(records).items():
        funcs = [d for d in decls if d["what"] == "func"]
        if len(funcs) < 2:
            continue
        first = funcs[0]
        for other in funcs[1:]:
            names_a = [n for n, _ in first["params"]]
            names_b = [n for n, _ in other["params"]]
            types_a = [t for _, t in first["params"]]
            types_b = [t for _, t in other["params"]]
            if (names_a != names_b and all(names_a) and all(names_b)) or types_a != types_b:
                yield _hit(other)


@system_check("declared_in_several_files")
def declared_in_several_files(records, params):
    for usr, decls in _entities(records).items():
        if decls[0]["linkage"] != "EXTERNAL":
            continue
        files = sorted({d["file"] for d in decls if not d["defn"]})
        if len(files) > 1:
            later = next(d for d in sorted(decls, key=lambda d: (d["file"], d["line"]))
                         if not d["defn"] and d["file"] == files[1])
            yield _hit(later)


@system_check("multiple_definitions")
def multiple_definitions(records, params):
    for usr, decls in _entities(records).items():
        defs = sorted((d for d in decls if d["defn"] and d["linkage"] == "EXTERNAL"), key=lambda d: (d["file"], d["line"]))
        for extra in defs[1:]:
            yield _hit(extra)


@system_check("external_used_in_one_unit")
def external_used_in_one_unit(records, params):
    refs = records.refs
    for usr, decls in _entities(records).items():
        defs = [d for d in decls if d["defn"] and d["linkage"] == "EXTERNAL"]
        if not defs or defs[0]["name"] == "main":
            continue
        used_in = refs.get(("usr", usr), set())
        if len(used_in) == 1:
            yield _hit(defs[0])


@system_check("external_object_unused")
def external_object_unused(records, params):
    refs = records.refs
    for usr, decls in _entities(records).items():
        defs = [d for d in decls if d["what"] == "var" and d["defn"] and d["linkage"] == "EXTERNAL"]
        if defs and not refs.get(("usr", usr)):
            yield _hit(defs[0])


# --- 2.3, 2.4: unused type declarations --------------------------------------------------------------------------

def _unreferenced(records, what: str):
    for r in _unique(records, what):
        if not records.refs.get(r["key"]):
            yield r


@system_check("typedef_unused")
def typedef_unused(records, params):
    for r in _unreferenced(records, "typedef"):
        yield _hit(r)


@system_check("tag_unused")
def tag_unused(records, params):
    typedef_tags = {r["of_tag"] for r in _unique(records, "typedef") if r["of_tag"]}
    for r in _unreferenced(records, "tag"):
        if r["name"] not in typedef_tags:
            yield _hit(r)

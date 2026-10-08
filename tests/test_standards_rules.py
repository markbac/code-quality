"""
Native standards rules against real C. Each case is a source in which every line that must be
reported ends with ``/* BAD */``; the rule has to report exactly those lines. A case without a
marker is a compliant source and must give no findings.
"""

from __future__ import annotations

import pytest
from standards_harness import analyse, marked_lines, reported

from fwlens.standards import load_standards

M, C, P = "misra-c-2012", "cert-c", "power-of-10"
M23, BC = "misra-c-2023", "barr-c-2018"
FW, AS, TS = "fwlens", "autosar-cpp14", "iso-ts-17961"

# (standard, rule id, source). Sources are kept small and every one compiles as plain C.
CASES: list[tuple[str, str, str]] = [
    # --- MISRA C:2012 ---
    (M, "15.1", "void f(int a) {\n if (a) goto end; /* BAD */\n a++;\n end: return;\n}\n"),
    (M, "21.3", "#include <stdlib.h>\nvoid f(void) { void *p = malloc(4); /* BAD */\n free(p); /* BAD */\n }\n"),
    (M, "21.4", "#include <setjmp.h> /* BAD */\njmp_buf b;\nvoid f(void) { longjmp(b, 1); /* BAD */\n }\n"),
    (M, "21.6", "#include <stdio.h>\nvoid f(void) { puts(\"x\"); /* BAD */\n }\n"),
    (M, "21.8", "#include <stdlib.h>\nvoid f(void) { abort(); /* BAD */\n }\n"),
    (M, "15.6", "void f(int a) {\n if (a) a++; /* BAD */\n while (a) a--; /* BAD */\n if (a) { a++; }\n}\n"),
    (M, "15.7", "void f(int a) {\n if (a == 1) { a++; } else if (a == 2) { a--; } /* BAD */\n}\n"),
    (M, "16.4", "void f(int a) {\n switch (a) { /* BAD */\n case 1: a++; break;\n }\n}\n"),
    (M, "16.5", "void f(int a) {\n switch (a) {\n case 1: a++; break;\n default: break; /* BAD */\n case 2: break;\n }\n}\n"),
    (M, "16.3", "void f(int a) {\n switch (a) {\n case 1: a++; /* BAD */\n case 2: a--; break;\n default: break;\n }\n}\n"),
    (M, "14.4", "void f(int a) {\n if (a != 1) { a++; }\n if (a != 0) { a--; }\n if (a + 1) { a--; } /* BAD */\n}\n"),
    (M, "13.4", "void f(int a, int b) {\n if ((a = b)) { a++; } /* BAD */\n}\n"),
    (M, "12.3", "int f(int a, int b) {\n return (a++, b); /* BAD */\n}\n"),
    (M, "11.5", "void f(void *p) {\n int *q = (int *)p; /* BAD */\n (void)q;\n}\n"),
    (M, "11.6", "void f(void) {\n void *p = (void *)1; /* BAD */\n (void)p;\n}\n"),
    (M, "17.7", "int g(void);\nvoid f(void) {\n g(); /* BAD */\n (void)g();\n}\n"),
    (M, "17.1", "#include <stdarg.h> /* BAD */\nvoid f(int n) {\n va_list ap;\n (void)n;\n}\n"),
    (M, "18.8", "void f(int n) {\n int a[n]; /* BAD */\n a[0] = 0;\n}\n"),
    (M, "19.2", "union u { int a; char b; }; /* BAD */\n"),
    (M, "20.4", "#define int long /* BAD */\n"),
    (M, "20.9", "#if FOO /* BAD */\n#endif\n"),
    (M, "20.10", "#define S(x) #x /* BAD */\n"),
    (M, "20.11", "#define S(x) #x ## x /* BAD */\n"),
    (M, "20.14", "#if 1\n#else\nint x;\n#endif\n"),
    (M, "7.1", "int a = 010; /* BAD */\n"),
    (M, "7.3", "long a = 1l; /* BAD */\n"),
    (M, "7.2", "unsigned int a = 0x80000000; /* BAD */\nunsigned int b = 0x80000000u;\n"),
    (M, "8.1", "static x; /* BAD */\n"),
    (M, "8.2", "int f(); /* BAD */\n"),
    (M, "8.8", "static int a;\nextern int a; /* BAD */\n"),
    (M, "8.14", "int *restrict p; /* BAD */\n"),
    (M, "6.1", "struct s { char a : 2; /* BAD */\n unsigned int b : 2; };\n"),
    (M, "6.2", "struct s { signed int a : 1; }; /* BAD */\n"),
    (M, "9.3", "int a[3] = { 1 }; /* BAD */\nint b[3] = { 1, 2, 3 };\n"),
    (M, "10.1", "void f(int a, unsigned b) {\n int c = a & b; /* BAD */\n (void)c;\n}\n"),
    (M, "10.3", "void f(float x) {\n int i = x; /* BAD */\n (void)i;\n}\n"),
    (M, "10.4", "int f(int a, unsigned b) {\n return a + b; /* BAD */\n}\n"),
    (M, "10.8", "void f(int a) {\n unsigned short s = (unsigned short)(a + a); /* BAD */\n (void)s;\n}\n"),
    (M, "12.2", "int f(int a) {\n return a << 40; /* BAD */\n}\n"),
    (M, "13.3", "void f(int a) {\n int b[2];\n b[0] = a++; /* BAD */\n}\n"),
    (M, "14.3", "void f(void) {\n if (1) { /* BAD */\n }\n}\n"),
    (M, "17.2", "int f(int a) { /* BAD */\n return a ? f(a - 1) : 0;\n}\n"),
    (M, "21.1", "#define __FOO 1 /* BAD */\n"),
    (M, "21.2", "int strlen(void); /* BAD */\n"),
    (M, "21.10", "#include <time.h>\nvoid f(void) {\n (void)time(0); /* BAD */\n}\n"),
    (M, "21.11", "#include <tgmath.h> /* BAD */\n"),
    (M, "2.7", "void f(int a) { /* BAD */\n}\n"),
    (M, "3.1", "/* outer /* nested */ /* BAD */\nint a;\n"),
    (M, "4.1", "const char *s = \"\\x41G\"; /* BAD */\nconst char *t = \"\\x41\" \"B\";\n"),
    (M, "5.3", "int x;\nvoid f(void) {\n int x = 0; /* BAD */\n (void)x;\n}\n"),
    (M, "2.2", "void f(void) {\n int a = 0;\n a + 1; /* BAD */\n (void)a;\n}\n"),
    # --- CERT C ---
    (C, "EXP33-C", "int f(void) {\n int a;\n return a; /* BAD */\n}\n"),
    (C, "INT33-C", "int f(int a, int b) {\n return a / 0; /* BAD */\n}\n"),
    (C, "MSC30-C", "#include <stdlib.h>\nint f(void) {\n return rand(); /* BAD */\n}\n"),
    (C, "ENV33-C", "#include <stdlib.h>\nvoid f(void) {\n system(\"ls\"); /* BAD */\n}\n"),
    (C, "STR31-C", "#include <string.h>\nvoid f(const char *s) {\n char b[4];\n strcpy(b, \"too long\"); /* BAD */\n (void)s;\n}\n"),
    (C, "FIO30-C", "#include <stdio.h>\nvoid f(char *s) {\n printf(s); /* BAD */\n}\n"),
    (C, "ERR33-C", "#include <stdio.h>\nvoid f(FILE *p) {\n fclose(p); /* BAD */\n}\n"),
    (C, "MEM34-C", "#include <stdlib.h>\nvoid f(void) {\n int a;\n free(&a); /* BAD */\n}\n"),
    (C, "FLP30-C", "void f(void) {\n for (float x = 0.0f; x < 1.0f; x += 0.1f) { /* BAD */\n }\n}\n"),
    (C, "PRE01-C", "#define SQ(x) x * x /* BAD */\n"),
    (C, "PRE02-C", "#define ADD(a, b) a + b /* BAD */\n"),
    (C, "PRE10-C", "#define SWAP(a, b) t = a; a = b; b = t /* BAD */\n"),
    (C, "DCL04-C", "void f(void) {\n int a, b; /* BAD */\n (void)a;\n (void)b;\n}\n"),
    (C, "EXP00-C", "int f(int a, int b) {\n return a + b * 2 << 1; /* BAD */\n}\n"),
    (C, "MSC01-C", "void f(int a) {\n switch (a) { /* BAD */\n case 1: break;\n }\n}\n"),
    # glibc's assert expands to "if (e) ; else ...": the macro's statement is not the author's
    (C, "EXP15-C", "#include <assert.h>\nint f(int *p) {\n    assert(p != 0);\n    return 1;\n}\n"),
    (M, "15.6", "#include <assert.h>\nint f(int *p) {\n    assert(p != 0);\n    return 1;\n}\n"),
    # --- MISRA C:2023 ---
    (M23, "D5.3", "typedef int thrd_t;\nint thrd_create(thrd_t *t, int (*f)(void *), void *a);\nstatic int worker(void *a) { (void)a; return 0; }\nvoid f(void) {\n thrd_t t;\n (void)thrd_create(&t, worker, 0); /* BAD */\n}\n"),
    (M23, "15.1", "void f(int a) {\n if (a) goto end; /* BAD */\n a++;\n end: return;\n}\n"),
    # --- BARR-C:2018 ---
    (BC, "3.5.a", "int a;\nint b;\n\tint c; /* BAD */\n"),
    (BC, "1.2.a", "int a; /* a very long comment that goes on and on past the eighty column limit of the standard */ /* BAD */\nint b;\n".replace(" /* BAD */\n", "\n").replace("standard */\n", "standard */ /* BAD */\n")),
    (BC, "1.7.d", "void f(int n) {\n while (n) {\n n--;\n continue; /* BAD */\n }\n}\n"),
    (BC, "1.7.a", "void f(void) {\n auto int x = 0; /* BAD */\n (void)x;\n}\n"),
    (BC, "5.2.b", "short value; /* BAD */\nlong other; /* BAD */\nint fine;\n"),
    (BC, "5.1.a", "typedef int Counter; /* BAD */\ntypedef int counter_t;\n"),
    (BC, "5.1.b", "struct point { int x; }; /* BAD */\ntypedef struct { int y; } pair_t;\n"),
    (BC, "5.3.a", "struct s { int a : 2; /* BAD */\n unsigned int b : 2; };\n"),
    (BC, "5.3.b", "int f(int a) {\n return a & 0xF0; /* BAD */\n}\nunsigned f2(unsigned a) {\n return a & 0xF0U;\n}\n"),
    (BC, "5.4.b.iv", "int f(float a, float b) {\n return a == b; /* BAD */\n}\n"),
    (BC, "6.1.e", "void MixedCase(void) { /* BAD */\n}\n"),
    (BC, "6.1.f", "#define lower_macro 1 /* BAD */\n#define UPPER_MACRO 1\n"),
    (BC, "6.3.b.iii", "#define SQUARE(x) ((x) * (x)) /* BAD */\n#define DOUBLE(x) ((x) + (x)) /* BAD */\n#define ONCE(x) ((x) + 1)\n"),
    (BC, "6.3.b.iv", "#define CHECK(x) if (!(x)) return /* BAD */\n"),
    (BC, "7.1.e", "void f(void) {\n int i = 0; /* BAD */\n int count = 0;\n (void)i;\n (void)count;\n}\n"),
    (BC, "7.1.j", "int counter; /* BAD */\nint g_counter;\n"),
    (BC, "7.1.k", "void f(void) {\n int *value = 0; /* BAD */\n int *p_value = 0;\n (void)value;\n (void)p_value;\n}\n"),
    (BC, "7.1.m", "void f(void) {\n _Bool flag = 0; /* BAD */\n _Bool b_flag = 0;\n (void)flag;\n (void)b_flag;\n}\n"),
    (BC, "7.2.d", "void f(void) {\n int *p_a; /* BAD */\n int *p_b = 0;\n (void)p_a;\n (void)p_b;\n}\n"),
    (BC, "8.2.b", "void f(int a, int b, int c) {\n if (a) {\n if (b) {\n if (c) { /* BAD */\n a++;\n }\n }\n }\n}\n"),
    (BC, "8.4.a", "void f(void) {\n int i;\n for (i = 0; i < 10; i++) { /* BAD */\n }\n for (i = 0; i < 1; i++) {\n }\n}\n"),
    (BC, "8.4.c", "void f(int a) {\n while (1) { /* BAD */\n a++;\n }\n for (;;) {\n a--;\n }\n}\n"),
    (BC, "8.5.b", "#include <stdlib.h>\nvoid f(void) {\n exit(1); /* BAD */\n}\n"),
    (BC, "8.6.a", "int f(int a) {\n return a == 0; /* BAD */\n}\nint g(int a) {\n return 0 == a;\n}\n"),
    (BC, "1.4.b", "int f(int a, int b, int c) {\n return a < b && c > 0; /* BAD */\n}\nint g(int a, int b) {\n return (a < b) && (b > 0);\n}\n"),
    (BC, "3.3.a", "void f(int a) {\n int b; b = a; /* BAD */\n (void)b;\n}\n"),
    (BC, "1.3.b", "void f(int a) { /* BAD */\n if (a) { /* BAD */\n a++;\n }\n}\n"),
    # --- NASA/JPL Power of 10 ---
    (P, "P10-1", "void f(int a) {\n if (a) goto end; /* BAD */\n end: return;\n}\n"),
    (P, "P10-3", "#include <stdlib.h>\nvoid f(void) {\n void *p = malloc(4); /* BAD */\n (void)p;\n}\n"),
    (P, "P10-9", "void f(int **p) { /* BAD */\n (void)p;\n}\n"),
    # --- FWLens built-in checks ---
    (FW, "SEC-1", "static const char password[] = \"letmein1\"; /* BAD */\nstatic const char user[] = \"letmein1\";\n"),
    (FW, "SEC-2", "const char *k = \"-----BEGIN RSA PRIVATE KEY-----\"; /* BAD */\nconst char *n = \"-----BEGIN CERTIFICATE-----\";\n"),
    (FW, "SEC-3", "const char *k = \"AKIAIOSFODNN7EXAMPLE\"; /* BAD */\nconst char *n = \"AKIA\";\n"),
    (FW, "SEC-4", "const char *u = \"https://admin:hunter2@host/x\"; /* BAD */\nconst char *v = \"https://host/x\";\n"),
    (FW, "SEC-5", "extern int MD5(const void *d);\nvoid f(void) {\n MD5(0); /* BAD */\n}\n"),
    (FW, "SEC-6", "const char *ip = \"192.168.1.10\"; /* BAD */\nconst char *v = \"1.2\";\n"),
    (FW, "DEAD-2", "static int unused(void) { return 1; } /* BAD */\nstatic int used(void) { return 2; }\nint pub(void) { return used(); }\n"),
    (FW, "DEAD-5", "void f(void) {\n int a = 0;\n int b; /* BAD */\n b = 3;\n a++;\n (void)a;\n}\n"),
    (FW, "ISR-1", "int flag;\nvolatile int vflag;\nvoid TIM2_IRQHandler(void) {\n flag = 1; /* BAD */\n vflag = 1;\n}\n"
                  "int get(void) { return flag + vflag; }\n"),
    (FW, "ISR-2", "void vTaskDelay(int t);\nvoid TIM2_IRQHandler(void) {\n vTaskDelay(1); /* BAD */\n}\nvoid task(void) {\n vTaskDelay(1);\n}\n"),
    (FW, "ISR-3", "int xQueueSend(void *q, void *i, int t);\nvoid ISR_uart(void) {\n xQueueSend(0, 0, 0); /* BAD */\n}\n"),
    (FW, "ISR-4", "#include <stdlib.h>\nvoid SysTick_Handler(void) {\n void *p = malloc(4); /* BAD */\n (void)p;\n}\n"),
    (FW, "ISR-5", "void X_IRQHandler(void) { /* BAD */\n" + " (void)0;\n" * 45 + "}\nvoid Y_IRQHandler(void) {\n (void)0;\n}\n"),
    # --- AUTOSAR C++14 (C subset) ---
    (AS, "A6-5-3", "void f(int a) {\n do { /* BAD */\n a++;\n } while (a < 3);\n}\n"),
    (AS, "A2-11-1", "volatile int v; /* BAD */\nint w;\n"),
    (AS, "A16-7-1", "#pragma pack(1) /* BAD */\nint a;\n"),
    (AS, "M18-2-1", "#include <stddef.h>\nstruct s { int a; };\nunsigned long f(void) {\n return offsetof(struct s, a); /* BAD */\n}\n"),
    (AS, "M19-3-1", "#include <errno.h>\nint f(void) {\n return errno; /* BAD */\n}\n"),
    (AS, "M18-0-5", "#include <string.h>\nvoid f(char *d, const char *s) {\n strcpy(d, s); /* BAD */\n}\n"),
    (AS, "A0-1-3", "static int unused(void) { return 1; } /* BAD */\nint pub(void) { return 0; }\n"),
    # --- ISO/IEC TS 17961 ---
    (TS, "syscall", "#include <stdlib.h>\nvoid f(void) {\n system(\"ls\"); /* BAD */\n}\n"),
    (TS, "addrescape", "int *f(void) {\n int a = 1;\n return &a; /* BAD */\n}\n"),
    (TS, "swtchdflt", "void f(int a) {\n switch (a) { /* BAD */\n case 1:\n break;\n }\n}\n"),
]


# Lexical checks added in #89 for guidelines that were manual. They are in both MISRA rule sets.
_LEXICAL = [
    ("7.5", "#include <stdint.h>\nint a = INT8_C(1);\nint b = INT8_C(1u); /* BAD */\nint c = INT16_C(-1); /* BAD */\nint d = INT32_C(0x10);\n"),
    ("8.16", "_Alignas(0) int a; /* BAD */\n_Alignas(8) int b;\n"),
    ("8.17", "_Alignas(8) _Alignas(16) int a; /* BAD */\n_Alignas(8) int b;\n"),
    ("11.10", "_Atomic(void) *p; /* BAD */\n_Atomic(void *) q;\n"),
    ("17.10", "#include <stdlib.h>\n_Noreturn int f(void) { abort(); } /* BAD */\n_Noreturn void g(void) { abort(); }\n"),
    ("23.3", "int f(int x) { return _Generic((x), default: 0); } /* BAD */\nint g(int x) { return _Generic((x), int: 1, default: 0); }\n"),
]
CASES += [(standard, rule, source) for standard in (M, M23) for rule, source in _LEXICAL]


def _id(case) -> str:
    return f"{case[0]}:{case[1]}"


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_rule_reports_exactly_the_marked_lines(case, tmp_path):
    standard, rule, source = case
    assert reported(tmp_path, source, standard, rule) == marked_lines(source)


def test_every_case_names_a_native_rule():
    standards = load_standards()
    for standard, rule, _ in CASES:
        assert any(c.type == "native" for c in standards[standard].rules[rule].checks), (standard, rule)


# --- whole-project checks: several files --------------------------------------------------------

PROJECTS: list[tuple[str, str, dict[str, str], dict[str, list[int]]]] = [
    # (standard, rule, files, {file: lines expected})
    (M, "8.6", {"a.c": "int g = 1;\n", "b.c": "int g = 2;\n"}, {"b.c": [1]}),
    (M, "8.5", {"a.h": "extern int g;\n", "b.h": "extern int g;\n", "a.c": "#include \"a.h\"\n#include \"b.h\"\nint g = 1;\n"},
     {"b.h": [1]}),
    (M, "8.7", {"a.c": "int g = 1;\nint f(void) { return g; }\n",
                "b.c": "extern int g;\nextern int f(void);\nint h(void) { return f() + g; }\n"},
     {"a.c": [2]}),
    (M, "2.3", {"a.c": "typedef int unused_t;\ntypedef int used_t;\nused_t v;\n"}, {"a.c": [1]}),
    (BC, "6.2.e", {"a.c": "int helper(void) { return 1; }\nint pub(void) { return helper(); }\n",
                   "b.c": "extern int pub(void);\nint use(void) { return pub(); }\n"}, {"a.c": [1]}),
    (BC, "4.2.c.ii", {"a.h": "int shared = 1;\nextern int other;\n", "a.c": "#include \"a.h\"\nint f(void) { return shared; }\n"}, {"a.h": [1]}),
    (BC, "4.2.c.i", {"a.h": "extern int shared;\nextern int f(void);\n", "a.c": "#include \"a.h\"\nint shared;\n"}, {"a.h": [1]}),
    (BC, "4.1.a", {"Bad-Name.c": "int a;\n", "good_name.c": "int b;\n"}, {"Bad-Name.c": [1]}),
    (BC, "4.3.c", {"mod.c": "int f(void) { return 0; }\n", "mod.h": "int f(void);\n"}, {"mod.c": [1]}),
    (BC, "4.3.d", {"a.c": "#include \"/abs/x.h\"\n"}, {"a.c": [1]}),
    (M, "5.8", {"a.c": "static int x;\n", "b.c": "static int x;\n"}, {}),
    (M, "5.9", {"a.c": "static int x;\nint f(void) { return x; }\n", "b.c": "static int x;\nint g(void) { return x; }\n"},
     {"a.c": [1], "b.c": [1]}),
]


@pytest.mark.parametrize("project", PROJECTS, ids=lambda p: f"{p[0]}:{p[1]}-{len(p[2])}files")
def test_system_rule_over_several_files(project, tmp_path):
    standard, rule, files, expected = project
    found = analyse(tmp_path, files, standard, [rule]).get(rule, [])
    got: dict[str, list[int]] = {}
    for f in found:
        got.setdefault(f.file.split("/")[-1], []).append(f.line)
    assert {k: sorted(v) for k, v in got.items()} == expected


def test_compliant_source_gives_no_findings_for_the_whole_standard(tmp_path):
    source = (
        "#include <stdint.h>\n"
        "static uint32_t add(uint32_t a, uint32_t b)\n{\n    return a + b;\n}\n"
        "uint32_t total(uint32_t x)\n{\n    uint32_t r = add(x, 1U);\n    return r;\n}\n"
    )
    found = analyse(tmp_path, source, M)
    assert {k: [f.line for f in v] for k, v in found.items() if k in ("15.1", "15.6", "21.3", "17.2", "10.1")} == {}


# --- schema: several checks, coverage, new engines ----------------------------------------------

def _doc(rule_extra=None, check=None):
    rule = {"id": "A1", "kind": "rule", "title": "t", "category": "must", "decidable": True, "scope": "single-tu",
            "check": check or {"type": "native", "engine": "detector", "match": {"name": "comma_operator"}}}
    rule.update(rule_extra or {})
    return {"schema_version": 1, "standard": {"id": "acme", "name": "Acme", "categories": ["must"]}, "rules": [rule]}


def test_a_rule_may_list_several_checks_and_declare_coverage():
    from pathlib import Path

    from fwlens.standards.rules import parse_standard
    two = [{"type": "native", "engine": "detector", "match": {"name": "comma_operator"}},
           {"type": "native", "engine": "source", "match": {"pattern": "goto"}}]
    rule = parse_standard(_doc({"coverage": "partial"}, two), Path("a.yaml")).rules["A1"]
    assert len(rule.checks) == 2 and rule.coverage == "partial"


@pytest.mark.parametrize("extra, check, message", [
    ({"coverage": "most"}, None, "coverage"),
    (None, {"type": "native", "engine": "detector", "match": {"name": "nope"}}, "known detector"),
    (None, {"type": "native", "engine": "system", "match": {}}, "known system"),
    (None, {"type": "native", "engine": "diagnostic", "match": {}}, "pattern"),
    (None, {"type": "native", "engine": "diagnostic", "match": {"option": 3}}, "option"),
    (None, {"type": "native", "engine": "source", "match": {"pattern": "("}}, "regular expression"),
])
def test_new_engines_validate_their_match(extra, check, message):
    from pathlib import Path

    from fwlens.standards.rules import RuleFileError, parse_standard
    with pytest.raises(RuleFileError, match=message):
        parse_standard(_doc(extra, check), Path("a.yaml"))


def test_partial_native_rule_without_findings_is_not_reported_as_compliant(tmp_path):
    from fwlens.standards import run_standards
    from fwlens.standards.matrix import build_matrix
    from standards_harness import _config

    from fwlens.config import StandardsConfig, StandardSelection
    from fwlens.parser.pipeline import run_pipeline
    (tmp_path / "app.c").write_text("int a;\n")
    (tmp_path / "config.yaml").write_text("tool:\n  target: native\nproject:\n  source_dir: .\n")
    config = _config(tmp_path)
    model = run_pipeline(config)
    config.standards = StandardsConfig(enabled=[StandardSelection(M, include_ids=["10.3", "15.1"])])
    rows = {r["id"]: r for r in build_matrix(run_standards(model, config))}
    assert rows["15.1"]["status"] == "no findings" and rows["15.1"]["checked_by"] == "native"
    assert rows["10.3"]["status"] == "no findings" and rows["10.3"]["checked_by"] == "native (partial)"


def test_bundled_standards_cover_every_guideline_with_a_check_type():
    standards = load_standards()
    assert {"misra-c-2012", "cert-c", "power-of-10"} <= set(standards)
    for standard in standards.values():
        for rule in standard.rules.values():
            assert rule.checks, rule.id
            assert len(rule.title) < 90, rule.id

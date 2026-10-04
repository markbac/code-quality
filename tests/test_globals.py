"""Regression tests for #61: only file-scope variables count as global reads and writes."""

from cparse import parse_functions, parse_model


def test_locals_are_not_globals(tmp_path):
    fns = parse_functions(tmp_path, """
int counter;
int local_only(int x){ int total = 0; total = x + 1; total++; return total; }
int shadow(void){ int counter = 5; counter = counter + 1; return counter; }
int real(void){ counter = counter + 1; return counter; }
""")
    assert fns["local_only"].global_reads == [] and fns["local_only"].global_writes == []
    assert fns["shadow"].global_reads == [] and fns["shadow"].global_writes == []
    assert fns["real"].global_reads == ["counter"] and fns["real"].global_writes == ["counter"]


def test_plain_assignment_target_is_a_write_not_a_read(tmp_path):
    fns = parse_functions(tmp_path, """
int g; int h;
int f(void);
int t(void){ if (h < (g = f())) { return 1; } return 0; }
""")
    assert fns["t"].global_writes == ["g"]
    assert fns["t"].global_reads == ["h"]


def test_same_named_statics_in_two_files_are_not_merged(tmp_path):
    model = parse_model(tmp_path, {
        "a.c": "static int state; void touch_a(void){ state = 1; }\n",
        "b.c": "static int state; int read_b(void){ return state; }\n",
    })
    by_file = {g.file.name: g for g in model.globals if g.name == "state"}
    from fwlens.graph.engines import compute_global_access_risk
    compute_global_access_risk(model)
    assert by_file["a.c"].writers == ["touch_a"] and by_file["a.c"].readers == []
    assert by_file["b.c"].readers == ["read_b"] and by_file["b.c"].writers == []

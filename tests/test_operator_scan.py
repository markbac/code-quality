"""Operators are read from their own token, not from whole-subtree token scans (#72)."""

import pytest

from cparse import parse_functions


def test_equality_wrapping_an_assignment_only_writes_the_assigned_variable(tmp_path):
    f = parse_functions(tmp_path, """
int a, b;
int w(int x) { return (a == (b = x)); }
""")["w"]
    assert "b" in f.global_writes
    assert "a" not in f.global_writes
    assert "a" in f.global_reads


def test_increment_and_decrement_are_writes(tmp_path):
    funcs = parse_functions(tmp_path, """
int up, down, post, other;
void f(void) { ++up; down--; post++; other = other + 1; }
""")
    assert set(funcs["f"].global_writes) == {"up", "down", "post", "other"}


def test_macro_use_does_not_inflate_complexity(tmp_path):
    funcs = parse_functions(tmp_path, """
int g;
#define SET(a, b) ((a) = (b))
#define BOTH(a, b) ((a) && (b))
int f(int x, int y) {
    int r = 0;
    SET(g, x + 1);
    r = BOTH(x, y) + (x == (y = 2));
    return r;
}
""")
    # Nothing in the macro bodies or the surrounding code adds a branch.
    assert funcs["f"].cyclomatic_complexity == 1


@pytest.mark.xfail(reason="operators written inside a macro body are not counted (known limitation, #72)",
                   strict=True)
def test_logical_operator_inside_macro_body_is_counted(tmp_path):
    f = parse_functions(tmp_path, """
#define BOTH(a, b) ((a) && (b))
int f(int x, int y) { return BOTH(x, y); }
""")["f"]
    assert f.cyclomatic_complexity == 2

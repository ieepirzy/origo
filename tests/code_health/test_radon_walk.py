"""The complexity walk, against radon's real output shape.

These fixtures are trimmed copies of genuine ``radon cc -j`` output, not
invented ones, because the whole point is that radon's shape is surprising:
methods appear twice, class blocks carry a derived aggregate, and
``--show-closures`` promotes closures while also leaving them nested.
"""

from tools.code_health.analyzers.radon_cc import _walk_functions

# Shape taken from `radon cc -j --show-closures origo` (radon 6.0.1).
REAL_SHAPE = [
    {"type": "function", "name": "token", "lineno": 683, "endline": 808, "complexity": 29, "closures": []},
    {
        "type": "class",
        "name": "_SafeHTTPSConnection",
        "lineno": 147,
        "endline": 181,
        # Derived from the method below, NOT an independent measurement.
        "complexity": 12,
        "methods": [
            {
                "type": "method",
                "name": "connect",
                "classname": "_SafeHTTPSConnection",
                "lineno": 151,
                "endline": 181,
                "complexity": 11,
                "closures": [],
            }
        ],
    },
    # The same method radon also nested above -- this is the double-count trap.
    {
        "type": "method",
        "name": "connect",
        "classname": "_SafeHTTPSConnection",
        "lineno": 151,
        "endline": 181,
        "complexity": 11,
        "closures": [],
    },
    # With --show-closures, radon promotes the closure under a qualified name
    # *and* leaves it nested under its parent (below).
    {"type": "function", "name": "https_open.build_conn", "lineno": 191, "endline": 194, "complexity": 1,
     "closures": []},
    {
        "type": "method",
        "name": "https_open",
        "classname": "_SafeHTTPSHandler",
        "lineno": 190,
        "endline": 195,
        "complexity": 1,
        "closures": [
            {"type": "function", "name": "build_conn", "lineno": 191, "endline": 194, "complexity": 1, "closures": []}
        ],
    },
]


def test_class_blocks_are_never_counted():
    """A class block's complexity is derived from methods counted separately."""
    walked = list(_walk_functions(REAL_SHAPE))
    assert not any(block["type"] == "class" for block in walked)


def test_each_method_is_counted_exactly_once():
    """Methods appear at top level AND under their class; count one."""
    walked = list(_walk_functions(REAL_SHAPE))
    connects = [b for b in walked if b["name"] == "connect"]
    assert len(connects) == 1, "method double-counted from the class's methods list"


def test_promoted_closures_are_counted_exactly_once():
    """--show-closures promotes and also nests; recursing would double-count."""
    walked = list(_walk_functions(REAL_SHAPE))
    build_conns = [b for b in walked if b["name"].endswith("build_conn")]
    assert len(build_conns) == 1
    assert build_conns[0]["name"] == "https_open.build_conn"


def test_aggregate_matches_hand_computation():
    """token 29 + connect 11 + build_conn 1 + https_open 1 = 42.

    The naive sum over the flat list (including the class block) would be 54.
    """
    walked = list(_walk_functions(REAL_SHAPE))
    assert sum(b["complexity"] for b in walked) == 42
    assert sum(b["complexity"] for b in REAL_SHAPE) == 54, "fixture no longer exercises the trap"


def test_methods_are_qualified_by_class():
    walked = list(_walk_functions(REAL_SHAPE))
    names = {b["qualified_name"] for b in walked}
    assert "_SafeHTTPSConnection.connect" in names
    assert "token" in names

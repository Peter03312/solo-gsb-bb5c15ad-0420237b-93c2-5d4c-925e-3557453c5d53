from app.diff import run_diff


def spec(servers=None, paths=None):
    d = {"openapi": "3.0.3", "info": {"title": "T", "version": "1"}, "paths": paths or {}}
    if servers is not None:
        d["servers"] = servers
    return d


OP200 = {"responses": {"200": {"description": "ok"}}}


def srv(findings):
    return [f for f in findings if str(f["rule_id"]).startswith("server")]


def keys(findings):
    return {(f["rule_id"], f["location"]) for f in findings}


def test_root_overridden_by_operation_no_finding():
    old = spec(
        servers=[{"url": "A"}],
        paths={"/x": {"get": {"servers": [{"url": "B"}], **OP200}}},
    )
    new = spec(
        servers=[{"url": "A"}, {"url": "C"}],
        paths={"/x": {"get": {"servers": [{"url": "B"}], **OP200}}},
    )
    assert srv(run_diff(old, new)) == []


def test_path_level_change_detected():
    old = spec(
        servers=[{"url": "A"}],
        paths={"/x": {"servers": [{"url": "B"}], "get": OP200}},
    )
    new = spec(
        servers=[{"url": "A"}],
        paths={"/x": {"servers": [{"url": "B2"}], "get": OP200}},
    )
    fs = srv(run_diff(old, new))
    assert keys(fs) == {("server-removed", "servers[B]"), ("server-added", "servers[B2]")}
    rm = next(f for f in fs if f["rule_id"] == "server-removed")
    assert rm["old_json_path"] == "/paths/x/servers/0"
    assert rm["new_json_path"] == "/paths/x/servers"
    assert rm["old_value"]["source"] == "path"
    assert rm["new_value"]["source"] == "path"
    assert rm["endpoint"] == "GET /x"


def test_root_changed_but_operation_overrides():
    old = spec(
        servers=[{"url": "A"}],
        paths={"/x": {"get": {"servers": [{"url": "B"}], **OP200}}},
    )
    new = spec(
        servers=[{"url": "C"}],
        paths={"/x": {"get": {"servers": [{"url": "B"}], **OP200}}},
    )
    assert srv(run_diff(old, new)) == []


def test_inherited_root_change():
    old = spec(servers=[{"url": "A"}], paths={"/x": {"get": OP200}})
    new = spec(servers=[{"url": "C"}], paths={"/x": {"get": OP200}})
    fs = srv(run_diff(old, new))
    assert {(f["rule_id"], f["severity"], f["location"]) for f in fs} == {
        ("server-removed", "breaking", "servers[A]"),
        ("server-added", "non_breaking", "servers[C]"),
    }


def test_both_default_no_finding():
    old = spec(paths={"/x": {"get": OP200}})
    new = spec(paths={"/x": {"get": OP200}})
    assert srv(run_diff(old, new)) == []


def test_default_to_explicit_only_added():
    old = spec(paths={"/x": {"get": OP200}})
    new = spec(servers=[{"url": "C"}], paths={"/x": {"get": OP200}})
    fs = srv(run_diff(old, new))
    assert keys(fs) == {("server-added", "servers[C]")}
    assert fs[0]["old_value"]["source"] == "default"
    assert fs[0]["new_json_path"] == "/servers/0"


def test_explicit_to_default_only_removed():
    old = spec(servers=[{"url": "A"}], paths={"/x": {"get": OP200}})
    new = spec(paths={"/x": {"get": OP200}})
    fs = srv(run_diff(old, new))
    assert keys(fs) == {("server-removed", "servers[A]")}
    assert fs[0]["new_value"]["source"] == "default"


def test_declaration_moved_same_url():
    old = spec(servers=[{"url": "A"}], paths={"/x": {"get": OP200}})
    new = spec(paths={"/x": {"get": {"servers": [{"url": "A"}], **OP200}}})
    assert srv(run_diff(old, new)) == []


def test_multiple_operations_isolated():
    old = spec(
        servers=[{"url": "A"}],
        paths={
            "/a": {"get": OP200},
            "/b": {"get": {"servers": [{"url": "B"}], **OP200}},
        },
    )
    new = spec(
        servers=[{"url": "C"}],
        paths={
            "/a": {"get": OP200},
            "/b": {"get": {"servers": [{"url": "B"}], **OP200}},
        },
    )
    fs = srv(run_diff(old, new))
    assert {f["endpoint"] for f in fs} == {"GET /a"}


def test_dedup_by_url():
    old = spec(
        servers=[{"url": "A"}, {"url": "A"}, {"url": "B"}],
        paths={"/x": {"get": OP200}},
    )
    new = spec(servers=[{"url": "A"}], paths={"/x": {"get": OP200}})
    fs = srv(run_diff(old, new))
    assert keys(fs) == {("server-removed", "servers[B]")}


def test_empty_operation_servers_falls_back_to_root():
    old = spec(
        servers=[{"url": "A"}],
        paths={"/x": {"get": {"servers": [], **OP200}}},
    )
    new = spec(
        servers=[{"url": "A"}, {"url": "C"}],
        paths={"/x": {"get": {"servers": [], **OP200}}},
    )
    fs = srv(run_diff(old, new))
    assert keys(fs) == {("server-added", "servers[C]")}
    assert fs[0]["old_value"]["source"] == "root"


def test_path_item_ref_servers_location():
    old = {
        "openapi": "3.0.3", "info": {"title": "T"},
        "servers": [{"url": "A"}],
        "paths": {"/x": {"$ref": "#/components/pathItems/Px"}},
        "components": {"pathItems": {"Px": {
            "servers": [{"url": "B"}], "get": OP200,
        }}},
    }
    new = {
        "openapi": "3.0.3", "info": {"title": "T"},
        "servers": [{"url": "A"}],
        "paths": {"/x": {"$ref": "#/components/pathItems/Px"}},
        "components": {"pathItems": {"Px": {
            "servers": [{"url": "B2"}], "get": OP200,
        }}},
    }
    fs = srv(run_diff(old, new))
    assert keys(fs) == {("server-removed", "servers[B]"), ("server-added", "servers[B2]")}
    rm = next(f for f in fs if f["rule_id"] == "server-removed")
    assert rm["old_json_path"] == "/components/pathItems/Px/servers/0"


def test_added_operation_no_server_conclusion():
    old = spec(servers=[{"url": "A"}], paths={"/x": {"get": OP200}})
    new = spec(
        servers=[{"url": "A"}],
        paths={
            "/x": {"get": OP200},
            "/y": {"get": {"servers": [{"url": "ZZZ"}], **OP200}},
        },
    )
    assert srv(run_diff(old, new)) == []


def test_operation_level_add_remove_and_value_shape():
    old = spec(paths={"/x": {"get": {
        "servers": [{"url": "B"}, {"url": "B2"}], **OP200,
    }}})
    new = spec(paths={"/x": {"get": {
        "servers": [{"url": "B2"}, {"url": "B3"}], **OP200,
    }}})
    fs = srv(run_diff(old, new))
    assert keys(fs) == {("server-removed", "servers[B]"), ("server-added", "servers[B3]")}
    rm = next(f for f in fs if f["rule_id"] == "server-removed")
    assert rm["old_json_path"] == "/paths/x/get/servers/0"
    assert rm["new_json_path"] == "/paths/x/get/servers"
    assert rm["old_value"]["servers"] == [
        {"url": "B", "pointer": "/paths/x/get/servers/0"},
        {"url": "B2", "pointer": "/paths/x/get/servers/1"},
    ]


if __name__ == "__main__":
    import sys
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                failed += 1
                print(f"FAIL {name}")
                import traceback
                traceback.print_exc()
    sys.exit(1 if failed else 0)

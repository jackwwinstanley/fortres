from src.b.extract import parse


def test_parse_keeps_only_allowed_values():
    a = 'Sure: {"product_type": "Network Edge Device", "auth_required": "no", "network_reachable": "yes", ' \
        '"impact_type": "remote code execution"}'
    assert parse(a) == {"product_type": "network_edge_device", "auth_required": "no",
                        "network_reachable": "yes", "impact_type": "remote_code_execution"}


def test_parse_rejects_made_up_values_and_garbage():
    assert parse('{"product_type": "spaceship", "auth_required": "maybe"}') == {
        "product_type": None, "auth_required": None, "network_reachable": None, "impact_type": None}
    assert parse("no json here")["impact_type"] is None


def test_guard_fixes_contradicted_labels():
    from src.b.extract import guard
    row = {"product_type": "wordpress_plugin", "auth_required": "yes", "network_reachable": "yes",
           "impact_type": "remote_code_execution"}
    out, ch = guard(row, "PHP Volunteer System lets an unauthenticated attacker upload files via upload.php")
    assert out["product_type"] == "web_application" and out["auth_required"] == "no" and len(ch) == 2
    out, ch = guard(row, "WordPress plugin Foo allows authenticated users to upload files")
    assert out["product_type"] == "wordpress_plugin" and out["auth_required"] == "yes" and ch == []

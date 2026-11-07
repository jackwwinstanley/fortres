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

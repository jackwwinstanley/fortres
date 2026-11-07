from src.b.explain import check_reason, cna_name


def test_cna_name():
    assert cna_name("psirt@cisco.com") == "Cisco"
    assert cna_name("cve@mitre.org") is None
    assert cna_name(None) is None


def test_check_reason_flags_invented_facts():
    facts = "- CVE: CVE-2026-1\n- Reported by: Cisco\n- Most similar past exploited CVE: CVE-2024-9 (Ivanti VPN, added to KEV in 2024)"
    assert check_reason("A remote code execution flaw (reported by Cisco) similar to CVE-2024-9 from 2024.", facts) == []
    assert "number 2023" in check_reason("Similar to an attack in 2023.", facts)
    assert "cve CVE-2021-44228" in check_reason("Like CVE-2021-44228.", facts)
    assert "name Fortinet" in check_reason("A flaw in Fortinet gear.", facts)

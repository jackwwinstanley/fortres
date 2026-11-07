"""Post-attack phrases that NVD/vendors may add to a description after a CVE is exploited.

They would leak the label, so texts.py removes them before anything is embedded and
text_features.py checks that none are left.
"""
import re

POST_ATTACK = re.compile(
    r"exploited in the wild|exploitation in the wild|exists in the wild|actively exploited|"
    r"known to be exploited|has been exploited|have been exploited|may have been exploited|"
    r"being exploited|reports? of exploitation|under active exploitation|"
    r"limited,? targeted exploitation|active exploitation",
    re.I,
)


def strip_post_attack(text: str) -> str:
    """Remove post-attack phrases and collapse the leftover whitespace."""
    return re.sub(r"\s+", " ", POST_ATTACK.sub("", text)).strip()

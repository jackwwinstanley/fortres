import numpy as np
import pandas as pd

from src.b.priors import knn_kev_rate, product_lexicon, product_names


def test_product_names_split_and_drop_generic():
    assert product_names("iOS, iPadOS, and macOS") == ["ipados", "macos"]  # 'ios' is shorter than 5 characters
    assert product_names("Multiple Products") == []
    assert product_names("Exchange Server") == ["exchange server"]


def test_product_lexicon_respects_cutoff_and_generic_filter():
    kev = pd.DataFrame({"cve_id": ["a", "b", "c"], "product": ["FortiOS", "Platform", "FortiOS"],
                        "date_added": ["2023-05-01", "2023-06-01", "2024-03-01"]})
    hist = pd.Series(["the platform allows"] * 50 + ["unrelated text"] * 50)
    lex = product_lexicon(kev, "2023-12-31", hist)
    assert lex.set_index("vendor").loc["fortios", "kev_count"] == 1      # the 2024 entry is after the cutoff
    assert "platform" not in set(lex["vendor"])                          # generic word, in 50% of history


def test_knn_kev_rate_uses_only_earlier_kev_labels():
    emb = np.eye(4, dtype="float32")
    emb[3] = emb[0]  # target 'd' is identical to 'a'
    texts = pd.DataFrame({"cve_id": ["a", "b", "c", "d"], "role": ["kev", "history", "kev", "replica_2024"],
                          "published": pd.to_datetime(["2020-01-01", "2020-01-01", "2020-01-01", "2024-02-01"]),
                          "kev_date_added": pd.to_datetime(["2021-01-01", None, "2024-06-01"])
                          .append(pd.DatetimeIndex([None]))})
    row = pd.Series(np.arange(4), index=texts["cve_id"])
    r = knn_kev_rate(pd.Series(["d"]), 2024, emb, row, texts, k=1)
    assert r[0] == 1.0                                   # nearest neighbour 'a' was on KEV by 2023-12-31
    r3 = knn_kev_rate(pd.Series(["d"]), 2024, emb, row, texts, k=3)
    assert abs(r3[0] - 1 / 3) < 1e-9                     # 'c' joined KEV after the cutoff, so it counts as 0

"""m12 TF-IDF (word 1-2 grams, min_df 5, sublinear tf) -> chi-square top 2000 terms -> logistic regression (C=1, balanced).
Everything (vocabulary, chi-square, model) fit on the training year only (training rows of the feature variant: in-fold).
Standalone score = decision function. Feature = the same value. Deterministic."""
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from src.b.zoo import harness as H
from src.b.zoo.util import memo

P = dict(ngram_range=(1, 2), min_df=5, max_features=100000, k=2000, C=1.0)


@memo("m12")
def score(train, apply, seed, env):
    pipe = make_pipeline(TfidfVectorizer(ngram_range=P["ngram_range"], min_df=P["min_df"], max_features=P["max_features"], sublinear_tf=True,
                                         token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_\-]+\b"),
                         SelectKBest(chi2, k=P["k"]), LogisticRegression(C=P["C"], class_weight="balanced", solver="liblinear", max_iter=1000))
    pipe.fit(list(train.desc), train.y)
    return pipe.decision_function(list(apply.desc))


def feature(train, apply, seed, env):
    return pd.DataFrame({"tfidf_lr": score(train, apply, seed, env)})


if __name__ == "__main__":
    H.run_method("m12_tfidf", score_fn=score, feature_fn=feature, deterministic=True, coverage_fn=feature, params={k: str(v) for k, v in P.items()})

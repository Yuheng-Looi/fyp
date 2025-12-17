# model_utils.py
import numpy as np
from sklearn.model_selection import train_test_split


def three_way_split(
    X,
    y,
    train_size=0.7,
    val_size=0.15,
    test_size=0.15,
    random_state=42,
    stratify=True
):
    assert abs(train_size + val_size + test_size - 1.0) < 1e-6

    strat = y if stratify else None

    X_train, X_tmp, y_train, y_tmp = train_test_split(
        X, y,
        test_size=(1 - train_size),
        random_state=random_state,
        stratify=strat
    )

    strat_tmp = y_tmp if stratify else None

    relative_test_size = test_size / (val_size + test_size)

    X_val, X_test, y_val, y_test = train_test_split(
        X_tmp, y_tmp,
        test_size=relative_test_size,
        random_state=random_state,
        stratify=strat_tmp
    )

    return X_train, X_val, X_test, y_train, y_val, y_test
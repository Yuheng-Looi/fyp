import numpy as np
import pandas as pd


class TriChannelScaler:
    """
    Tri-Channel Feature Scaler (Environment-Adaptive)

    For each feature x, generate:
    1) Log channel   : log1p(x)                    -> distribution shape
    2) Ratio channel : x / P95_benign              -> scale invariance
    3) Delta channel : (x - Median) / IQR_benign   -> deviation from normal

    Statistics are fitted using BENIGN traffic only.
    """

    def __init__(
        self,
        benign_label: int = 4,
        epsilon: float = 1e-6,
        ratio_clip: float = 10.0,
        delta_clip: float = 10.0,
    ):
        """
        Parameters
        ----------
        benign_label : int
            Label ID representing Normal / Benign traffic.
        epsilon : float
            Small constant to avoid division by zero.
        ratio_clip : float
            Upper bound for ratio channel to prevent explosion.
        delta_clip : float
            Symmetric bound for delta channel to stabilize learning.
        """
        self.benign_label = benign_label
        self.epsilon = epsilon
        self.ratio_clip = ratio_clip
        self.delta_clip = delta_clip

        self.stats_ = {}
        self.feature_names_ = []

    # --------------------------------------------------
    # FIT
    # --------------------------------------------------
    def fit(self, X: pd.DataFrame, labels: pd.Series):
        """
        Fit scaler statistics using BENIGN traffic only.

        Parameters
        ----------
        X : pd.DataFrame
            Feature matrix (raw CICFlow features).
        labels : pd.Series
            Corresponding labels.

        Returns
        -------
        self
        """
        if not isinstance(X, pd.DataFrame):
            raise TypeError("X must be a pandas DataFrame")

        benign_mask = labels == self.benign_label
        Xb = X.loc[benign_mask]

        if Xb.empty:
            raise ValueError(
                "TriChannelScaler.fit(): No benign samples found. "
                "Cannot compute baseline statistics."
            )

        self.feature_names_ = X.columns.tolist()
        self.stats_.clear()

        for col in self.feature_names_:
            col_vals = Xb[col].astype(float).to_numpy()

            median = np.median(col_vals)
            q75, q25 = np.percentile(col_vals, [75, 25])
            iqr = q75 - q25
            p95 = np.percentile(col_vals, 95)

            self.stats_[col] = {
                "median": median,
                "iqr": iqr if iqr > 0 else self.epsilon,
                "p95": p95 if p95 > 0 else self.epsilon,
            }

        return self

    # --------------------------------------------------
    # TRANSFORM
    # --------------------------------------------------
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Apply Tri-Channel transformation to ALL samples.

        Parameters
        ----------
        X : pd.DataFrame
            Feature matrix to transform.

        Returns
        -------
        pd.DataFrame
            Tri-Channel transformed features.
        """
        if not self.stats_:
            raise RuntimeError(
                "TriChannelScaler.transform(): scaler has not been fitted."
            )

        # Ensure feature order consistency
        X = X[self.feature_names_]

        outputs = []

        for col in self.feature_names_:
            stats = self.stats_[col]
            x = X[col].astype(float)

            # -------------------------------
            # Channel 1: Log (shape)
            # -------------------------------
            # Ensure non-negative (network features should be >= 0 anyway)
            x_log = np.clip(x.to_numpy(), a_min=0.0, a_max=None)
            log_vals = np.log1p(x_log)
            log_feat = pd.Series(
                log_vals, index=X.index, name=f"{col}_log"
            )

            # -------------------------------
            # Channel 2: Ratio (scale)
            # -------------------------------
            ratio_vals = x / stats["p95"]
            ratio_vals = ratio_vals.clip(upper=self.ratio_clip)
            ratio_feat = ratio_vals.rename(f"{col}_ratio")

            # -------------------------------
            # Channel 3: Delta (deviation)
            # -------------------------------
            delta_vals = (x - stats["median"]) / stats["iqr"]
            delta_vals = delta_vals.clip(
                lower=-self.delta_clip, upper=self.delta_clip
            )
            delta_feat = delta_vals.rename(f"{col}_delta")

            outputs.extend([log_feat, ratio_feat, delta_feat])

        return pd.concat(outputs, axis=1)

    # --------------------------------------------------
    # UTILITIES
    # --------------------------------------------------
    def get_feature_names_out(self):
        """
        Return output feature names after Tri-Channel expansion.
        """
        names = []
        for col in self.feature_names_:
            names.extend(
                [f"{col}_log", f"{col}_ratio", f"{col}_delta"]
            )
        return names
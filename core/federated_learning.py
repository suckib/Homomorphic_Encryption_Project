"""
Federated Learning with Homomorphic Secure Aggregation (Paillier FedAvg).

Simulates a multi-institutional clinical setting (e.g., 3 hospitals collaborating 
on diagnostic classification) without exposing local patient data or raw gradients.
"""

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import numpy as np
from sklearn.datasets import load_breast_cancer
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from core.paillier_he import PaillierEngine


@dataclass
class ClientData:
    client_id: str
    name: str
    X_train: np.ndarray
    y_train: np.ndarray
    sample_count: int
    positive_ratio: float


@dataclass
class RoundMetrics:
    round_num: int
    global_accuracy: float
    global_loss: float
    global_f1: float
    client_accuracies: Dict[str, float]
    local_train_time_ms: float
    encryption_time_ms: float
    aggregation_time_ms: float
    decryption_time_ms: float
    ciphertext_sample_snippet: str
    verified_match: bool


class LogisticRegressionClassifier:
    """Lightweight, vectorized logistic regression for federated optimization."""

    def __init__(self, n_features: int, lr: float = 0.05):
        self.weights = np.zeros(n_features, dtype=np.float64)
        self.bias = 0.0
        self.lr = lr

    @staticmethod
    def _sigmoid(z: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(z, -25.0, 25.0)))

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        linear = np.dot(X, self.weights) + self.bias
        return self._sigmoid(linear)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X) >= 0.5).astype(int)

    def compute_loss(self, X: np.ndarray, y: np.ndarray) -> float:
        preds = np.clip(self.predict_proba(X), 1e-7, 1.0 - 1e-7)
        return float(-np.mean(y * np.log(preds) + (1.0 - y) * np.log(1.0 - preds)))

    def train_epoch(self, X: np.ndarray, y: np.ndarray, epochs: int = 5) -> None:
        m = len(y)
        if m == 0:
            return
        for _ in range(epochs):
            preds = self.predict_proba(X)
            diff = preds - y
            grad_w = np.dot(X.T, diff) / m
            grad_b = float(np.mean(diff))

            self.weights -= self.lr * grad_w
            self.bias -= self.lr * grad_b

    def get_parameters(self) -> Tuple[np.ndarray, float]:
        return self.weights.copy(), float(self.bias)

    def set_parameters(self, weights: np.ndarray, bias: float) -> None:
        self.weights = weights.copy()
        self.bias = float(bias)


class FederatedDataset:
    """Prepares and partitions clinical diagnostic records across distributed hospital clients."""

    def __init__(self, non_iid: bool = False, test_size: float = 0.20, seed: int = 42):
        self.non_iid = non_iid
        self.seed = seed
        self.scaler = StandardScaler()

        # Load Wisconsin Diagnostic Breast Cancer dataset
        raw = load_breast_cancer()
        X = raw.data
        y = raw.target  # 0: Malignant, 1: Benign
        self.feature_names = list(raw.feature_names)
        self.target_names = list(raw.target_names)

        X_train_full, self.X_test, y_train_full, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=seed, stratify=y
        )

        X_train_scaled = self.scaler.fit_transform(X_train_full)
        self.X_test_scaled = self.scaler.transform(self.X_test)

        self.clients = self._partition_clients(X_train_scaled, y_train_full)

    def _partition_clients(self, X: np.ndarray, y: np.ndarray) -> List[ClientData]:
        n_samples = len(y)
        client_configs = [
            ("client_1", "St. Jude Medical Center"),
            ("client_2", "Metro General Hospital"),
            ("client_3", "University Oncology Clinic")
        ]

        if not self.non_iid:
            # IID split: Stratified uniform random partition
            rng = np.random.default_rng(self.seed)
            indices = np.arange(n_samples)
            rng.shuffle(indices)
            splits = np.array_split(indices, 3)
        else:
            # Non-IID split: Feature & prevalence heterogeneity across hospitals
            idx_class0 = np.where(y == 0)[0]
            idx_class1 = np.where(y == 1)[0]

            # Hospital 1: High malignant volume (75% class 0)
            # Hospital 2: High screening/benign volume (80% class 1)
            # Hospital 3: Balanced community cohort
            split_0 = np.array_split(idx_class0, [int(len(idx_class0) * 0.50), int(len(idx_class0) * 0.70)])
            split_1 = np.array_split(idx_class1, [int(len(idx_class1) * 0.20), int(len(idx_class1) * 0.65)])

            splits = [
                np.concatenate([split_0[0], split_1[0]]),
                np.concatenate([split_0[1], split_1[1]]),
                np.concatenate([split_0[2], split_1[2]])
            ]

        clients = []
        for idx, (cid, name) in enumerate(client_configs):
            idx_set = splits[idx]
            cX = X[idx_set]
            cy = y[idx_set]
            clients.append(ClientData(
                client_id=cid,
                name=name,
                X_train=cX,
                y_train=cy,
                sample_count=len(cy),
                positive_ratio=float(np.mean(cy)) if len(cy) > 0 else 0.0
            ))

        return clients


class SecureFederatedCoordinator:
    """Orchestrates FedAvg rounds with Paillier homomorphic parameter aggregation."""

    def __init__(self, dataset: FederatedDataset, key_length: int = 1024, lr: float = 0.08):
        self.dataset = dataset
        self.engine = PaillierEngine(key_length=key_length)
        self.n_features = dataset.X_test_scaled.shape[1]
        self.lr = lr

        self.global_model = LogisticRegressionClassifier(self.n_features, lr=lr)
        self.client_models = [
            LogisticRegressionClassifier(self.n_features, lr=lr)
            for _ in range(len(dataset.clients))
        ]

    def evaluate_model(self, model: LogisticRegressionClassifier) -> Dict[str, float]:
        X_test = self.dataset.X_test_scaled
        y_test = self.dataset.y_test
        preds = model.predict(X_test)
        probas = model.predict_proba(X_test)

        acc = float(accuracy_score(y_test, preds))
        f1 = float(f1_score(y_test, preds, zero_division=0))
        auc = float(roc_auc_score(y_test, probas))
        loss = model.compute_loss(X_test, y_test)

        return {"accuracy": acc, "f1": f1, "auc": auc, "loss": loss}

    def train_round(self, round_num: int, local_epochs: int = 3) -> RoundMetrics:
        # Step 1: Local client training from latest global parameters
        current_w, current_b = self.global_model.get_parameters()
        total_samples = sum(c.sample_count for c in self.dataset.clients)

        t_train_start = time.perf_counter()
        local_params = []
        client_accs = {}

        for i, client in enumerate(self.dataset.clients):
            self.client_models[i].set_parameters(current_w, current_b)
            self.client_models[i].train_epoch(client.X_train, client.y_train, epochs=local_epochs)
            lw, lb = self.client_models[i].get_parameters()
            local_params.append((lw, lb))

            # Record local evaluation on global test set
            client_eval = self.evaluate_model(self.client_models[i])
            client_accs[client.name] = client_eval["accuracy"]

        train_time_ms = (time.perf_counter() - t_train_start) * 1000

        # Step 2: Client-side local encryption of weights and bias
        t_enc_start = time.perf_counter()
        encrypted_client_payloads = []
        for lw, lb in local_params:
            enc_w = [self.engine.encrypt(float(val)) for val in lw]
            enc_b = self.engine.encrypt(float(lb))
            encrypted_client_payloads.append((enc_w, enc_b))
        enc_time_ms = (time.perf_counter() - t_enc_start) * 1000

        # Capture a representative ciphertext snippet for UI inspection
        snippet = self.engine.ciphertext_snippet(encrypted_client_payloads[0][0][0], length=70)

        # Step 3: Untrusted server homomorphic aggregation
        # Enc(W_avg) = sum_k (alpha_k * Enc(W_k)), alpha_k = n_k / N
        t_agg_start = time.perf_counter()
        aggregated_enc_w = None
        aggregated_enc_b = None

        for k, (enc_w, enc_b) in enumerate(encrypted_client_payloads):
            alpha = float(self.dataset.clients[k].sample_count / total_samples)

            # Homomorphic scalar multiplication
            scaled_w = [item * alpha for item in enc_w]
            scaled_b = enc_b * alpha

            if aggregated_enc_w is None:
                aggregated_enc_w = scaled_w
                aggregated_enc_b = scaled_b
            else:
                # Homomorphic ciphertext addition
                aggregated_enc_w = [a + b for a, b in zip(aggregated_enc_w, scaled_w)]
                aggregated_enc_b = aggregated_enc_b + scaled_b

        agg_time_ms = (time.perf_counter() - t_agg_start) * 1000

        # Step 4: Authorized decryption of global model parameters
        t_dec_start = time.perf_counter()
        decrypted_w = np.array([self.engine.decrypt(cw) for cw in aggregated_enc_w], dtype=np.float64)
        decrypted_b = float(self.engine.decrypt(aggregated_enc_b))
        dec_time_ms = (time.perf_counter() - t_dec_start) * 1000

        # Step 5: Verification against exact plaintext FedAvg baseline
        plain_w = np.zeros(self.n_features, dtype=np.float64)
        plain_b = 0.0
        for k, (lw, lb) in enumerate(local_params):
            alpha = self.dataset.clients[k].sample_count / total_samples
            plain_w += alpha * lw
            plain_b += alpha * lb

        diff = float(np.max(np.abs(decrypted_w - plain_w)) + abs(decrypted_b - plain_b))
        verified_match = diff < 1e-3

        # Update global model with aggregated weights
        self.global_model.set_parameters(decrypted_w, decrypted_b)
        global_eval = self.evaluate_model(self.global_model)

        return RoundMetrics(
            round_num=round_num,
            global_accuracy=global_eval["accuracy"],
            global_loss=global_eval["loss"],
            global_f1=global_eval["f1"],
            client_accuracies=client_accs,
            local_train_time_ms=train_time_ms,
            encryption_time_ms=enc_time_ms,
            aggregation_time_ms=agg_time_ms,
            decryption_time_ms=dec_time_ms,
            ciphertext_sample_snippet=snippet,
            verified_match=verified_match
        )

    def train_isolated_baselines(self, total_epochs: int = 15) -> Dict[str, float]:
        """Trains models strictly on local hospital data with no federation (isolated baseline)."""
        isolated_accs = {}
        for client in self.dataset.clients:
            m = LogisticRegressionClassifier(self.n_features, lr=self.lr)
            m.train_epoch(client.X_train, client.y_train, epochs=total_epochs)
            eval_res = self.evaluate_model(m)
            isolated_accs[client.name] = eval_res["accuracy"]
        return isolated_accs

    def train_centralized_upper_bound(self, total_epochs: int = 15) -> float:
        """Hypothetical upper bound: trains on pooled data from all hospitals."""
        X_all = np.vstack([c.X_train for c in self.dataset.clients])
        y_all = np.concatenate([c.y_train for c in self.dataset.clients])
        m = LogisticRegressionClassifier(self.n_features, lr=self.lr)
        m.train_epoch(X_all, y_all, epochs=total_epochs)
        return self.evaluate_model(m)["accuracy"]

# Homomorphic Encryption Workbench

An interactive dashboard and reference implementation exploring the mechanics, algebra, and threat models of **Homomorphic Encryption (HE)**, with primary focus on the Paillier additively homomorphic cryptosystem.

Built for privacy-preserving computation research and educational demonstration.

**Live Deployment:** [https://homomorphic-encryption-calculator.streamlit.app/](https://homomorphic-encryption-calculator.streamlit.app/)

---

## Architecture & Features

The project is structured into four functional modules:

1. **Encrypted Calculator (`pages/1_Calculator.py`):**
   - Live homomorphic evaluations:
     - Additive homomorphism: $\text{Enc}(m_1) \cdot \text{Enc}(m_2) \bmod n^2 = \text{Enc}(m_1 + m_2 \bmod n)$
     - Subtraction: $\text{Enc}(m_1) \cdot (\text{Enc}(m_2))^{-1} \bmod n^2 = \text{Enc}(m_1 - m_2 \bmod n)$
     - Scalar multiplication: $(\text{Enc}(m_1))^k \bmod n^2 = \text{Enc}(k \cdot m_1 \bmod n)$
   - Configurable key lengths ($512, 1024, 2048, 3072$ bits) with latency benchmarking.
   - Demonstration of semantic security (IND-CPA randomized blinding).

2. **Privacy-Preserving Aggregation (`pages/2_Salary_Aggregation.py`):**
   - Multi-party confidential benchmarking protocol.
   - Participants encrypt contributions locally with the public key.
   - An untrusted aggregator computes sum and mean homomorphically without learning individual inputs.
   - Authorized decryption yields correct aggregates with zero leakage of constituent values.

3. **Cryptographic Trace (`pages/3_Cryptographic_Trace.py`):**
   - Step-by-step symbolic and numerical walkthrough using small, human-verifiable moduli.
   - Inspects prime selection, Carmichael totient ($\lambda$), generator selection ($g = n + 1$), modular inverses ($\mu$), and blinding factors ($r$).

4. **Foundations & Theory (`pages/4_Theory_and_Foundations.py`):**
   - Cryptographic taxonomy: Partially (PHE) vs. Leveled/Somewhat (SHE/LHE) vs. Fully Homomorphic (FHE).
   - Mathematical proof of Paillier additive homomorphism.
   - Applications in electronic voting, AML compliance, and private inference.

5. **Secure Federated Learning (`pages/5_Federated_Learning.py`):**
   - Collaborative multi-hospital diagnostic classification (Wisconsin Diagnostic Breast Cancer).
   - Simulates 3 hospital cohorts training local logistic classifiers under IID and non-IID conditions.
   - Server executes encrypted FedAvg parameter aggregation: $\text{Enc}(W_{\text{global}}) = \sum_{k} \frac{n_k}{N} \text{Enc}(W^{(k)})$.
   - Prevents gradient leakage and data reconstruction attacks against honest-but-curious aggregators.
   - Includes empirical comparison against isolated local baselines and theoretical centralized bounds.

---

## Installation & Usage

### Prerequisites
- Python 3.10 or higher

### Setup

```bash
# Clone or navigate to the workspace
cd he-calculator

# Install dependencies
pip install -r requirements.txt

# Run the Streamlit dashboard
streamlit run app.py
```

The application will be accessible at `http://localhost:8501`.

---

## Dependencies

- **`streamlit`** — Interactive web interface
- **`phe` (`python-paillier`)** — Optimized Paillier cryptosystem engine (Data61 / CSIRO)
- **`numpy`** — Vectorized matrix operations and model gradient calculations
- **`scikit-learn`** — Clinical dataset loader, preprocessing, and validation metrics

---

## Mathematical Summary: Paillier Scheme

- **Plaintext space:** $\mathbb{Z}_n$
- **Ciphertext space:** $\mathbb{Z}_{n^2}^*$
- **Public Key:** $(n, g)$ where $n = p \cdot q$
- **Private Key:** $(\lambda, \mu)$ where $\lambda = \text{lcm}(p-1, q-1)$ and $\mu = (L(g^\lambda \bmod n^2))^{-1} \bmod n$
- **Encryption:** $c = g^m \cdot r^n \bmod n^2$ with random blinding factor $r \in \mathbb{Z}_n^*$
- **Decryption:** $m = L(c^\lambda \bmod n^2) \cdot \mu \bmod n$ where $L(u) = \frac{u - 1}{n}$
- **Hardness Assumption:** Decisional Composite Residuosity Assumption (DCRA)

"""
Educational Foundations of Homomorphic Encryption
Taxonomy, mathematical structure, applications, and self-assessment.
"""

import os
import sys
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from utils.visualization import get_custom_css

st.set_page_config(page_title="Foundations & Theory", layout="wide")
st.markdown(get_custom_css(), unsafe_allow_html=True)

st.title("Foundations of Homomorphic Encryption")
st.caption("A reference guide to cryptosystem classifications, algebraic properties, and threat models.")
st.markdown("---")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Conceptual Model",
    "Scheme Taxonomy",
    "Paillier Derivation",
    "Application Domains",
    "Knowledge Verification"
])

with tab1:
    st.subheader("What is Homomorphic Encryption?")

    st.markdown("""
    Standard encryption schemes (e.g., AES-GCM, RSA-OAEP) are intentionally non-malleable: modifying a ciphertext yields 
    garbage or authentication errors upon decryption. While this is essential for transport security, it prohibits delegating 
    computation on encrypted data to external servers.

    **Homomorphic Encryption (HE)** provides an algebraic homomorphism between the ciphertext space $(\\mathcal{C}, \\odot)$ 
    and the plaintext space $(\\mathcal{M}, \\oplus)$:

    $$\\text{Dec}(c_1 \\odot c_2) = \\text{Dec}(c_1) \\oplus \\text{Dec}(c_2) = m_1 \\oplus m_2$$

    More generally, for any function $f$ representable as an arithmetic circuit of supported operations:
    """)

    st.latex(r"\text{Dec}\Big(\text{Eval}\big(f, \text{Enc}(x_1), \dots, \text{Enc}(x_k)\big)\Big) = f(x_1, \dots, x_k)")

    st.markdown("""
    ### Structural Comparison

    | Dimension | Conventional Cloud Processing | Homomorphic Evaluation |
    | :--- | :--- | :--- |
    | **Data Ingestion** | Plaintext in server memory | Pure ciphertext blobs |
    | **Server Trust Requirement** | High (trusted server model) | Zero (honest-but-curious adversary) |
    | **Key Distribution** | Evaluator holds decryption key / TLS termination | Evaluator holds *only* public evaluation key |
    | **Data Breach Surface** | Plaintext memory extraction risks exposure | Memory dumps yield IND-CPA pseudorandom data |
    """)

    st.markdown("""
    ### Historical Context
    - **1978:** Rivest, Adleman, and Dertouzos formalize the concept of "on-the-fly" privacy homomorphisms.
    - **1999:** Pascal Paillier introduces the composite residuosity-based additive cryptosystem.
    - **2009:** Craig Gentry constructs the first candidate Fully Homomorphic Encryption (FHE) scheme via ideal lattices and bootstrapping.
    - **2011–Present:** Modern second- and third-generation lattice schemes (BGV, BFV, CKKS, TFHE) achieve practical performance for vectors and neural network inference.
    """)

with tab2:
    st.subheader("Taxonomy of Homomorphic Systems")

    st.markdown("""
    Schemes are categorized by the operations they support and their circuit evaluation depth:
    """)

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("""
        <div class="he-card">
            <h5 style="color: #3fb950; margin-top: 0;">Partially Homomorphic (PHE)</h5>
            <p style="font-size: 0.85rem; color: #8b949e;">Supports one arithmetic operation for unbounded depth.</p>
            <ul style="font-size: 0.82rem; color: #c9d1d9; line-height: 1.6;">
                <li><strong>Unpadded RSA / ElGamal:</strong> Multiplicative only (<code>Enc(m₁) · Enc(m₂) = Enc(m₁ · m₂)</code>)</li>
                <li><strong>Paillier / Goldwasser-Micali:</strong> Additive only</li>
                <li><strong>Performance:</strong> Microsecond operations, negligible noise accumulation</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown("""
        <div class="he-card">
            <h5 style="color: #d29922; margin-top: 0;">Somewhat / Leveled (SHE / LHE)</h5>
            <p style="font-size: 0.85rem; color: #8b949e;">Supports both addition and multiplication for a predetermined depth.</p>
            <ul style="font-size: 0.82rem; color: #c9d1d9; line-height: 1.6;">
                <li><strong>Schemes:</strong> BGN (1 multiply), unbootstrapped BFV / BGV / CKKS</li>
                <li><strong>Limitation:</strong> Multiplications introduce inherent noise that grows exponentially until decryption fails.</li>
                <li><strong>Performance:</strong> Millisecond vector operations</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        st.markdown("""
        <div class="he-card">
            <h5 style="color: #bc8cff; margin-top: 0;">Fully Homomorphic (FHE)</h5>
            <p style="font-size: 0.85rem; color: #8b949e;">Supports arbitrary circuits of unbounded depth.</p>
            <ul style="font-size: 0.82rem; color: #c9d1d9; line-height: 1.6;">
                <li><strong>Mechanism:</strong> Periodically executes <em>bootstrapping</em> (evaluating the decryption circuit homomorphically) to refresh noise.</li>
                <li><strong>Schemes:</strong> TFHE (fast gate bootstrapping), CKKS with bootstrapping, BGV/BFV with relinearization.</li>
                <li><strong>Performance:</strong> High computational and memory overhead</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("##### Scheme Comparison Matrix")
    st.markdown("""
    | Scheme | Family | Homomorphic Algebra | Primary Message Space | Noise Dynamic | Target Applications |
    | :--- | :--- | :--- | :--- | :--- | :--- |
    | **Paillier** | PHE | Additive $(\\mathbb{Z}_n, +)$ | Scalars $\\mathbb{Z}_n$ | None (algebraic) | Voting, aggregation, private sums |
    | **BFV / BGV** | SHE/FHE | Ring $(\\mathbb{R}_t, +, \\times)$ | Packed Integer Vectors | Grows with depth; refreshed by bootstrapping | Exact integer circuits, private SQL |
    | **CKKS** | SHE/FHE | Approximate $(\\mathbb{C}^N, +, \\times)$ | Packed Real/Complex Vectors | Rescaling controls fixed-point error | Private ML inference, PCA, regression |
    | **TFHE** | FHE | Boolean / Torus LUTs | Bits, Small Integers | Reset per gate (fast bootstrap) | Control flow, comparison, non-linear activations |
    """)

with tab3:
    st.subheader("Mathematical Derivation: The Paillier Scheme")

    st.markdown("""
    Paillier is defined over the multiplicative group $\\mathbb{Z}_{n^2}^*$, where $n = p \\cdot q$ for large primes $p$ and $q$.
    Security rests on the **Decisional Composite Residuosity Assumption (DCRA)**: deciding whether a given $z \\in \\mathbb{Z}_{n^2}^*$ 
    is an $n$-th residue modulo $n^2$ is computationally intractable without knowing the factorization of $n$.
    """)

    st.markdown("##### 1. Key Generation")
    st.markdown(r"""
    1. Select large primes $p$ and $q$ uniformly at random, such that $\gcd(p \cdot q, (p-1)(q-1)) = 1$.
    2. Compute the RSA modulus $n = p \cdot q$ and $\lambda = \text{lcm}(p-1, q-1)$.
    3. Choose generator $g = n + 1 \in \mathbb{Z}_{n^2}^*$.
    4. Compute modular multiplier $\mu = \left( L(g^\lambda \bmod n^2) \right)^{-1} \bmod n$, where $L(u) = \frac{u - 1}{n}$.
    """)
    st.latex(r"\text{Public Key: } (n, g) \qquad \text{Private Key: } (\lambda, \mu)")

    st.markdown("##### 2. Encryption")
    st.markdown("For message $m \\in \\mathbb{Z}_n$, sample random blinding factor $r \\xleftarrow{R} \\mathbb{Z}_n^*$:")
    st.latex(r"c = g^m \cdot r^n \bmod n^2")

    st.markdown("##### 3. Decryption")
    st.latex(r"m = L(c^\lambda \bmod n^2) \cdot \mu \bmod n")

    st.markdown("##### 4. Proof of Additive Homomorphism")
    st.markdown("""
    Given two valid ciphertexts $c_1 = g^{m_1} r_1^n \\bmod n^2$ and $c_2 = g^{m_2} r_2^n \\bmod n^2$:
    """)
    st.latex(r"""
    \begin{aligned}
    c_1 \cdot c_2 \bmod n^2 &= \left( g^{m_1} r_1^n \right) \cdot \left( g^{m_2} r_2^n \right) \bmod n^2 \\
    &= g^{m_1 + m_2} \cdot (r_1 r_2)^n \bmod n^2 \\
    &= \text{Enc}(m_1 + m_2 \bmod n, \; r_1 r_2 \bmod n)
    \end{aligned}
    """)
    st.markdown("""
    Because $r_1 r_2 \\bmod n$ is uniformly distributed in $\\mathbb{Z}_n^*$, the product ciphertext is a valid, 
    freshly blinded encryption of $m_1 + m_2 \\bmod n$.
    """)

with tab4:
    st.subheader("Applied Cryptographic Protocols")

    col_a1, col_a2 = st.columns(2)
    with col_a1:
        st.markdown("""
        <div class="he-card">
            <h5 style="color: #79c0ff; margin-top: 0;">Electronic Voting & Tallying</h5>
            <p style="font-size: 0.85rem; color: #8b949e;">
                Ballots are represented as one-hot or numeric vectors encrypted under the election public key.
                The tally authority multiplies all encrypted ballots:
            </p>
            <code style="font-size: 0.78rem;">c_tally = ∏ cᵢ mod n² = Enc(∑ voteᵢ)</code>
            <p style="font-size: 0.85rem; color: #c9d1d9; margin-top: 8px;">
                Only the final tally is decrypted. Zero-knowledge proofs (ZKPs) ensure ballots contain valid votes without revealing selections.
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="he-card">
            <h5 style="color: #58a6ff; margin-top: 0;">Cross-Institutional Financial Compliance</h5>
            <p style="font-size: 0.85rem; color: #8b949e;">
                Financial organizations can evaluate private set intersections (PSI) and aggregate transaction velocities 
                for anti-money-laundering (AML) monitoring without disclosing customer transaction ledgers.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with col_a2:
        st.markdown("""
        <div class="he-card">
            <h5 style="color: #3fb950; margin-top: 0;">Private Clinical & Genomic Research</h5>
            <p style="font-size: 0.85rem; color: #8b949e;">
                Multiple research hospitals contribute patient biomarkers. Statistical aggregations 
                (odds ratios, variance, regression coefficients) are computed without patient data leaving institutional perimeter boundaries.
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="he-card">
            <h5 style="color: #bc8cff; margin-top: 0;">Private Machine Learning Inference (MLaaS)</h5>
            <p style="font-size: 0.85rem; color: #8b949e;">
                Clients encrypt inputs and transmit to model hosting providers. The server computes linear layers 
                (matrix multiplications) and polynomial activations directly on ciphertexts, preserving model weights 
                and client query privacy simultaneously.
            </p>
        </div>
        """, unsafe_allow_html=True)

with tab5:
    st.subheader("Self-Assessment")
    st.caption("Verify your understanding of homomorphic principles and security properties.")

    # Stateful quiz handling
    if "quiz_state" not in st.session_state:
        st.session_state.quiz_state = {
            "submitted": False,
            "score": 0
        }

    q1 = st.radio(
        "1. What security guarantee prevents an observer from identifying identical plaintexts from their ciphertexts?",
        [
            "Collision resistance",
            "IND-CPA (Indistinguishability under Chosen-Plaintext Attack)",
            "Deterministic pseudo-randomness",
            "Unconditional information-theoretic secrecy"
        ],
        key="quiz_q1"
    )

    q2 = st.radio(
        "2. Which mathematical operation on Paillier ciphertexts evaluates plaintext addition?",
        [
            "Ciphertext addition modulo n",
            "Ciphertext modular exponentiation c₁ᶜ² mod n",
            "Ciphertext multiplication modulo n²",
            "Bitwise XOR of raw ciphertext bytes"
        ],
        key="quiz_q2"
    )

    q3 = st.radio(
        "3. Why is Paillier classified as Partially Homomorphic (PHE) rather than Fully Homomorphic (FHE)?",
        [
            "It does not support multiplication between two ciphertexts",
            "It can only encrypt 8-bit integers",
            "Its keys expire after a bounded number of evaluations",
            "Its modulus is not prime"
        ],
        key="quiz_q3"
    )

    q4 = st.radio(
        "4. In Paillier encryption c = gᵐ · rⁿ mod n², what role does r play?",
        [
            "It specifies the public modulus",
            "It is a random blinding factor that provides semantic security",
            "It represents the secret key for decryption",
            "It accelerates modular reduction"
        ],
        key="quiz_q4"
    )

    q5 = st.radio(
        "5. Which modern lattice-based FHE scheme is specifically designed for approximate arithmetic over real numbers?",
        [
            "Goldwasser-Micali",
            "BFV",
            "CKKS",
            "RSA-OAEP"
        ],
        key="quiz_q5"
    )

    if st.button("Evaluate Answers", type="primary"):
        expected_answers = {
            "quiz_q1": "IND-CPA (Indistinguishability under Chosen-Plaintext Attack)",
            "quiz_q2": "Ciphertext multiplication modulo n²",
            "quiz_q3": "It does not support multiplication between two ciphertexts",
            "quiz_q4": "It is a random blinding factor that provides semantic security",
            "quiz_q5": "CKKS"
        }

        user_responses = {
            "quiz_q1": q1,
            "quiz_q2": q2,
            "quiz_q3": q3,
            "quiz_q4": q4,
            "quiz_q5": q5
        }

        score = sum(1 for k, ans in expected_answers.items() if user_responses[k] == ans)
        st.session_state.quiz_state = {
            "submitted": True,
            "score": score
        }

    if st.session_state.quiz_state["submitted"]:
        score = st.session_state.quiz_state["score"]
        st.markdown("---")
        st.markdown(f"**Score: {score} / 5**")
        if score == 5:
            st.success("All answers correct.")
        elif score >= 3:
            st.info(f"Score: {score}/5. Review the Taxonomy and Paillier Derivation tabs.")
        else:
            st.warning(f"Score: {score}/5. Re-read the introductory concepts.")

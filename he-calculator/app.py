"""
Homomorphic Encryption Interactive Workbench
Main dashboard and navigation overview.
"""

import os
import sys
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.visualization import get_custom_css

st.set_page_config(
    page_title="Homomorphic Encryption Workbench",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(get_custom_css(), unsafe_allow_html=True)

st.title("Homomorphic Encryption Workbench")
st.caption("Cryptographic computing and privacy-preserving protocol demonstrations using the Paillier cryptosystem.")
st.markdown("---")

col_main, col_summary = st.columns([1.8, 1.2])

with col_main:
    st.markdown("""
    ### Overview

    Homomorphic encryption allows an untrusted evaluator to perform computations directly on ciphertexts. 
    Upon decryption with the private key, the resulting plaintext matches the evaluation performed on the raw inputs:

    $$\\text{Dec}(\\text{Eval}(c_1, c_2, \\dots)) = f(m_1, m_2, \\dots)$$

    This workbench focuses on the **Paillier cryptosystem**, an additively homomorphic scheme based on the 
    **Decisional Composite Residuosity (DCR)** assumption. It demonstrates how encrypted operations work in practice,
    how privacy-preserving aggregation protocols function, and the underlying number theory.
    """)

    st.markdown("""
    ### Modules in this Project

    - **Calculator** (`pages/1_Calculator.py`): Interactive evaluation of homomorphic addition, subtraction, and scalar multiplication with live key-length selection and runtime metrics.
    - **Salary Demo** (`pages/2_Salary_Aggregation.py`): A multi-party aggregation simulation where employees encrypt their compensation locally and an untrusted aggregator computes sum and mean without learning individual values.
    - **Under The Hood** (`pages/3_Cryptographic_Trace.py`): Detailed step-by-step trace of Paillier key generation, randomized encryption, and ciphertext multiplication using human-verifiable small moduli.
    - **Learn HE** (`pages/4_Theory_and_Foundations.py`): Theoretical taxonomy (PHE vs. SHE vs. FHE), mathematical proofs, security assumptions, and knowledge verification.
    """)

with col_summary:
    st.markdown(r"""
    <div class="he-card">
        <h4 style="color: #79c0ff; margin-top: 0;">Homomorphic Properties</h4>
        <p style="font-size: 0.88rem; color: #8b949e; margin-bottom: 8px;">Paillier Scheme ($\mathbb{Z}_{n^2}^*$)</p>
        <ul style="font-size: 0.88rem; color: #c9d1d9; padding-left: 20px; line-height: 1.6;">
            <li><strong>Encrypted Addition:</strong><br><code>Enc(m₁) · Enc(m₂) mod n² = Enc(m₁ + m₂)</code></li>
            <li><strong>Scalar Multiplication:</strong><br><code>Enc(m₁)ᵏ mod n² = Enc(k · m₁)</code></li>
            <li><strong>Semantic Security:</strong><br>IND-CPA secure via random blinding factor <code>r ∈ ℤₙ*</code></li>
            <li><strong>Ciphertext × Ciphertext:</strong><br><span style="color: #f85149;">Not supported</span> (requires FHE like BFV/CKKS)</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="he-card">
        <h4 style="color: #d29922; margin-top: 0;">Implementation Stack</h4>
        <ul style="font-size: 0.85rem; color: #c9d1d9; padding-left: 20px; line-height: 1.6;">
            <li>Python 3.10+</li>
            <li><code>python-paillier</code> (production PHE engine)</li>
            <li>Custom step-by-step arithmetic module for symbolic tracing</li>
            <li>Streamlit web interface</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")
st.markdown(
    '<div style="text-align: center; color: #484f58; font-size: 0.8rem;">'
    'Homomorphic Encryption Workbench &bull; Cryptographic Evaluation Suite'
    '</div>',
    unsafe_allow_html=True
)

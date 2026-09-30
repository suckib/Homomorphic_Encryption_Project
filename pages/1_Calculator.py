"""
Encrypted Arithmetic Calculator
Evaluates Paillier additive homomorphism and scalar multiplication.
"""

import os
import sys
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.paillier_he import PaillierEngine
from utils.visualization import (
    get_custom_css, pipeline_html, comparison_card, timing_card
)

st.set_page_config(page_title="Encrypted Calculator", layout="wide")
st.markdown(get_custom_css(), unsafe_allow_html=True)

st.title("Encrypted Calculator")
st.caption("Perform homomorphic evaluations directly on ciphertexts and verify against plaintext baselines.")
st.markdown("---")


@st.cache_resource
def get_engine(key_length: int) -> PaillierEngine:
    return PaillierEngine(key_length=key_length)


with st.sidebar:
    st.subheader("Cryptographic Parameters")
    key_size = st.select_slider(
        "Modulus Bit Length (n)",
        options=[512, 1024, 2048, 3072],
        value=1024,
        help="Bit length of modulus n = p * q. 2048-bit minimum recommended for standard security margins."
    )
    if key_size < 2048:
        st.warning("512 / 1024-bit keys are for demonstration only.")
    else:
        st.success("2048+ bit modulus matches standard security criteria.")

    st.markdown("---")
    st.markdown("""
    **Evaluation Rules:**
    - **Addition:** `c_sum = c_a · c_b mod n²`
    - **Subtraction:** `c_diff = c_a · (c_b)⁻¹ mod n²`
    - **Scalar Multiplication:** `c_prod = c_aᵇ mod n²` (Operand B is treated as a plaintext scalar).
    """)

engine = get_engine(key_size)

# Input controls
col_inputs, col_op = st.columns([2, 1])

with col_inputs:
    st.subheader("Operands")
    c1, c2 = st.columns(2)
    with c1:
        val_a = st.number_input("Operand A (m₁)", value=42.0, step=1.0, format="%.2f")
    with c2:
        val_b = st.number_input("Operand B (m₂ or scalar k)", value=18.0, step=1.0, format="%.2f")

with col_op:
    st.subheader("Operation")
    operation_label = st.radio(
        "Select Operation",
        [
            "Addition: Enc(A) + Enc(B)",
            "Subtraction: Enc(A) - Enc(B)",
            "Scalar Multiply: Enc(A) × B"
        ]
    )

op_map = {
    "Addition: Enc(A) + Enc(B)": "add",
    "Subtraction: Enc(A) - Enc(B)": "subtract",
    "Scalar Multiply: Enc(A) × B": "multiply"
}
selected_op = op_map[operation_label]

st.markdown("---")

pipeline_steps = [
    ("Plaintext Input", "plaintext"),
    ("Encryption (Client)", "encrypt"),
    ("Homomorphic Eval (Server)", "compute"),
    ("Decryption (Client)", "decrypt"),
    ("Verification", "result")
]

st.markdown(pipeline_html(pipeline_steps, active_step=-1), unsafe_allow_html=True)

if st.button("Execute Homomorphic Pipeline", type="primary", use_container_width=True):
    # Perform computation without artificial delays
    result = engine.compute(val_a, val_b, selected_op)
    st.session_state["calc_result"] = result

if "calc_result" in st.session_state:
    res = st.session_state["calc_result"]

    st.markdown(
        comparison_card(
            f"Evaluation: {res.operation}",
            res.plaintext_result,
            res.decrypted_result,
            res.match
        ),
        unsafe_allow_html=True
    )

    st.markdown(
        timing_card(
            res.encrypt_time_ms,
            res.compute_time_ms,
            res.decrypt_time_ms
        ),
        unsafe_allow_html=True
    )

    with st.expander("Ciphertext Inspection", expanded=True):
        st.markdown(
            "Below are the hexadecimal fragments of the evaluated ciphertexts in $\\mathbb{Z}_{n^2}^*$."
        )
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.caption("Ciphertext A")
            st.markdown(f'<div class="ciphertext-box">{res.ciphertext_a_snippet}</div>', unsafe_allow_html=True)
        with col_c2:
            st.caption("Ciphertext B")
            st.markdown(f'<div class="ciphertext-box">{res.ciphertext_b_snippet}</div>', unsafe_allow_html=True)

        st.caption("Result Ciphertext (Output of Evaluator)")
        st.markdown(f'<div class="ciphertext-box">{res.ciphertext_result_snippet}</div>', unsafe_allow_html=True)

st.markdown("---")

# Semantic Security Demonstration (Independent section, avoids nested button bug)
st.subheader("Semantic Security (IND-CPA)")
st.markdown("""
Paillier encryption uses randomized blinding: $c = g^m \\cdot r^n \\bmod n^2$ where $r \\xleftarrow{R} \\mathbb{Z}_n^*$.
Even when encrypting the exact same message repeatedly, each ciphertext is statistically independent and indistinguishable.
""")

test_val = st.number_input("Sample message to encrypt multiple times", value=val_a, step=1.0, format="%.2f", key="sec_test_val")
if st.button("Generate 3 Independent Ciphertexts"):
    for i in range(3):
        enc = engine.encrypt(test_val)
        st.text(f"Ciphertext #{i + 1}: {engine.ciphertext_snippet(enc, 90)}")

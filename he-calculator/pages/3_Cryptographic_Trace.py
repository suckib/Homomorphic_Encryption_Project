"""
Mathematical Walkthrough of the Paillier Cryptosystem
Traces key generation, encryption, homomorphic evaluation, and decryption.
"""

import os
import sys
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.educational import EducationalPaillier, PaillierStep
from utils.visualization import get_custom_css

st.set_page_config(page_title="Cryptographic Trace", layout="wide")
st.markdown(get_custom_css(), unsafe_allow_html=True)

st.title("Cryptographic Trace (Step-by-Step)")
st.caption("Inspect the exact modular arithmetic of the Paillier scheme using small, human-verifiable parameters.")
st.markdown("---")

# Initialize session state for persistent trace
if "edu_engine" not in st.session_state:
    engine = EducationalPaillier()
    st.session_state.edu_engine = engine
    st.session_state.edu_key_steps = engine.generate_keys()
    st.session_state.edu_enc_data = None
    st.session_state.edu_eval_data = None

engine: EducationalPaillier = st.session_state.edu_engine


def render_step(step: PaillierStep):
    st.markdown(f"""
    <div class="he-card">
        <h5 style="margin: 0 0 6px 0; color: #79c0ff;">Step {step.step_number}: {step.title}</h5>
        <p style="color: #c9d1d9; font-size: 0.85rem; margin-bottom: 8px;">{step.description}</p>
    </div>
    """, unsafe_allow_html=True)

    st.latex(step.formula)

    cols = st.columns(len(step.values))
    for idx, (label, val) in enumerate(step.values.items()):
        with cols[idx]:
            st.metric(label, f"{val:,}" if isinstance(val, int) else str(val))
    st.markdown("")


# Section 1: Key Generation
st.subheader("1. Key Pair Derivation")
st.markdown(
    r"Derives public parameters $(n, g)$ and private parameters $(\lambda, \mu)$ "
    "from two distinct primes where $\\gcd(\\text{lcm}(p-1, q-1), n) = 1$."
)

if st.button("Regenerate Prime Parameters"):
    engine = EducationalPaillier()
    st.session_state.edu_engine = engine
    st.session_state.edu_key_steps = engine.generate_keys()
    st.session_state.edu_enc_data = None
    st.session_state.edu_eval_data = None
    st.rerun()

for step in st.session_state.edu_key_steps:
    render_step(step)

col_pub, col_priv = st.columns(2)
with col_pub:
    st.markdown(f"""
    <div class="he-card">
        <h5 style="margin: 0 0 6px 0; color: #3fb950;">Public Key</h5>
        <div style="font-family: monospace; font-size: 0.85rem; color: #d8e1ec;">
            n = {engine.n}<br>
            n² = {engine.n_sq}<br>
            g = {engine.g}
        </div>
    </div>
    """, unsafe_allow_html=True)
with col_priv:
    st.markdown(f"""
    <div class="he-card">
        <h5 style="margin: 0 0 6px 0; color: #f85149;">Private Key</h5>
        <div style="font-family: monospace; font-size: 0.85rem; color: #d8e1ec;">
            λ = {engine.lam}<br>
            μ = {engine.mu}
        </div>
    </div>
    """, unsafe_allow_html=True)

# Section 2: Encryption
st.markdown("---")
st.subheader("2. Encryption of Plaintext Messages")

c_in1, c_in2 = st.columns(2)
with c_in1:
    m1 = st.number_input("Message 1 (m₁)", value=42, min_value=0, max_value=max(1, engine.n - 1), step=1)
with c_in2:
    m2 = st.number_input("Message 2 (m₂)", value=18, min_value=0, max_value=max(1, engine.n - 1), step=1)

if st.button("Encrypt Plaintexts", type="primary"):
    c1, steps1 = engine.encrypt_step_by_step(m1)
    c2, steps2 = engine.encrypt_step_by_step(m2)
    st.session_state.edu_enc_data = {
        "m1": m1,
        "m2": m2,
        "c1": c1,
        "c2": c2,
        "steps1": steps1,
        "steps2": steps2
    }
    st.session_state.edu_eval_data = None

if st.session_state.edu_enc_data is not None:
    enc_data = st.session_state.edu_enc_data
    tab_m1, tab_m2 = st.tabs([f"Encryption Trace: m₁ = {enc_data['m1']}", f"Encryption Trace: m₂ = {enc_data['m2']}"])
    with tab_m1:
        for s in enc_data["steps1"]:
            render_step(s)
    with tab_m2:
        for s in enc_data["steps2"]:
            render_step(s)

    # Section 3: Homomorphic Evaluation
    st.markdown("---")
    st.subheader("3. Homomorphic Addition & Decryption")
    st.markdown("Multiplying ciphertexts in $\\mathbb{Z}_{n^2}^*$ adds their corresponding plaintexts in $\\mathbb{Z}_n$.")

    if st.button("Evaluate Homomorphic Product (c₁ · c₂ mod n²)"):
        c_sum, add_steps = engine.homomorphic_add_step_by_step(enc_data["c1"], enc_data["c2"])
        decrypted, dec_steps = engine.decrypt_step_by_step(c_sum)
        st.session_state.edu_eval_data = {
            "c_sum": c_sum,
            "add_steps": add_steps,
            "decrypted": decrypted,
            "dec_steps": dec_steps
        }

    if st.session_state.edu_eval_data is not None:
        eval_data = st.session_state.edu_eval_data
        st.markdown("##### Homomorphic Step")
        for s in eval_data["add_steps"]:
            render_step(s)

        st.markdown("##### Decryption Step")
        for s in eval_data["dec_steps"]:
            render_step(s)

        expected = (enc_data["m1"] + enc_data["m2"]) % engine.n
        recovered = eval_data["decrypted"]
        is_verified = (recovered == expected)

        st.markdown(f"""
        <div class="{'he-card-success' if is_verified else 'he-card-warning'}" style="margin-top: 15px;">
            <div style="display: flex; justify-content: space-around; align-items: center;">
                <div>
                    <span style="color: #8b949e; font-size: 0.8rem;">Expected: (m₁ + m₂) mod n</span>
                    <div style="font-size: 1.5rem; font-weight: 600; color: #e6edf3;">{expected}</div>
                </div>
                <div style="font-size: 1.3rem; color: #484f58;">&harr;</div>
                <div>
                    <span style="color: #8b949e; font-size: 0.8rem;">Decrypted: Dec(c₁ · c₂ mod n²)</span>
                    <div style="font-size: 1.5rem; font-weight: 600; color: #79c0ff;">{recovered}</div>
                </div>
            </div>
            <div style="text-align: center; margin-top: 10px; font-weight: 500; color: {'#3fb950' if is_verified else '#d29922'};">
                {'Mathematical verification confirmed.' if is_verified else 'Verification failed.'}
            </div>
        </div>
        """, unsafe_allow_html=True)

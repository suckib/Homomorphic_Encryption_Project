"""
Privacy-Preserving Aggregation Demonstration
Simulates a multi-party private compensation benchmarking scenario.
"""

import os
import sys
import time
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.paillier_he import PaillierEngine
from utils.visualization import get_custom_css

st.set_page_config(page_title="Privacy-Preserving Aggregation", layout="wide")
st.markdown(get_custom_css(), unsafe_allow_html=True)

st.title("Privacy-Preserving Aggregation")
st.caption("Secure Multi-Party Computation pattern: summing private inputs over an untrusted aggregator.")
st.markdown("---")


@st.cache_resource
def get_engine():
    return PaillierEngine(key_length=1024)

engine = get_engine()

# Protocol Overview
st.markdown("""
<div class="he-card">
    <h4 style="color: #79c0ff; margin-top: 0;">Threat Model & Protocol Flow</h4>
    <p style="color: #c9d1d9; font-size: 0.9rem; line-height: 1.6;">
        Multiple participants submit sensitive numeric contributions (e.g., salaries, telemetry, bids).
        The aggregator is honest-but-curious: it follows protocol execution correctly but attempts to deduce 
        individual participant inputs from network traffic or memory dumps.
    </p>
    <ol style="color: #8b949e; font-size: 0.85rem; line-height: 1.6; margin-bottom: 0;">
        <li><strong>Local Key Generation:</strong> Aggregator or trusted authority holds the private key (λ, μ) and publishes the public key (n, g).</li>
        <li><strong>Client-Side Encryption:</strong> Each participant encrypts their contribution: <code>cᵢ = Enc(mᵢ)</code>.</li>
        <li><strong>Untrusted Homomorphic Sum:</strong> Aggregator calculates <code>c_total = ∏ cᵢ mod n² = Enc(∑ mᵢ)</code>.</li>
        <li><strong>Homomorphic Mean:</strong> Aggregator computes <code>c_mean = (c_total)^(1/N) mod n² = Enc((∑ mᵢ) / N)</code>.</li>
        <li><strong>Authorized Release:</strong> Only the final aggregate is decrypted; individual inputs remain computationally hidden under DCR hardness.</li>
    </ol>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

st.subheader("Participant Inputs")

col_setup, col_meta = st.columns([1, 2])
with col_setup:
    num_participants = st.slider("Number of Participants", min_value=3, max_value=8, value=5)

names = ["Alice", "Bob", "Carol", "David", "Eve", "Frank", "Grace", "Heidi"]
default_salaries = [85000.0, 92000.0, 78000.0, 115000.0, 105000.0, 98000.0, 88000.0, 120000.0]

if "salaries" not in st.session_state or len(st.session_state.salaries) != num_participants:
    st.session_state.salaries = default_salaries[:num_participants]

# Grid layout for participant cards
input_cols = st.columns(num_participants)
for idx in range(num_participants):
    with input_cols[idx]:
        st.session_state.salaries[idx] = st.number_input(
            names[idx],
            value=st.session_state.salaries[idx],
            step=1000.0,
            format="%.0f",
            key=f"p_input_{idx}"
        )

st.markdown("---")

if st.button("Execute Aggregation Protocol", type="primary", use_container_width=True):
    salaries = st.session_state.salaries[:num_participants]
    n_count = len(salaries)

    # Stage 1: Client-side local encryption
    st.subheader("1. Client-Side Encryption")
    st.caption("Inputs are encrypted locally using the public key before transmission.")

    enc_salaries = []
    enc_times = []

    stage1_cols = st.columns(n_count)
    for idx in range(n_count):
        t0 = time.perf_counter()
        enc = engine.encrypt(salaries[idx])
        t_enc = (time.perf_counter() - t0) * 1000

        enc_salaries.append(enc)
        enc_times.append(t_enc)

        with stage1_cols[idx]:
            st.markdown(f"""
            <div class="he-card" style="padding: 10px; font-size: 0.8rem;">
                <strong style="color: #79c0ff;">{names[idx]}</strong><br>
                <span style="color: #8b949e;">Ciphertext:</span>
                <div class="ciphertext-box" style="font-size: 0.65rem; max-height: 45px; margin-top: 4px;">
                    {engine.ciphertext_snippet(enc, 36)}
                </div>
                <span style="color: #8b949e; font-size: 0.75rem;">Time: {t_enc:.1f} ms</span>
            </div>
            """, unsafe_allow_html=True)

    # Stage 2: Server-side aggregation
    st.markdown("---")
    st.subheader("2. Aggregator Evaluation (Untrusted Cloud)")
    st.caption("The aggregator combines ciphertexts without possession of private decryption parameters.")

    t0 = time.perf_counter()
    enc_total = engine.batch_sum(enc_salaries)
    # Server calculates mean homomorphically using scalar multiplication
    scalar_inv_n = 1.0 / n_count
    enc_mean = enc_total * scalar_inv_n
    agg_time = (time.perf_counter() - t0) * 1000

    col_agg1, col_agg2 = st.columns(2)
    with col_agg1:
        st.markdown(f"""
        <div class="he-card">
            <h5 style="color: #58a6ff; margin: 0 0 6px 0;">Aggregated Ciphertext (Sum)</h5>
            <div class="ciphertext-box">{engine.ciphertext_snippet(enc_total, 110)}</div>
        </div>
        """, unsafe_allow_html=True)
    with col_agg2:
        st.markdown(f"""
        <div class="he-card">
            <h5 style="color: #58a6ff; margin: 0 0 6px 0;">Evaluated Ciphertext (Mean = Sum × 1/N)</h5>
            <div class="ciphertext-box">{engine.ciphertext_snippet(enc_mean, 110)}</div>
        </div>
        """, unsafe_allow_html=True)

    # Stage 3: Decryption & Verification
    st.markdown("---")
    st.subheader("3. Decryption & Baseline Validation")

    t0 = time.perf_counter()
    decrypted_total = engine.decrypt(enc_total)
    decrypted_mean = engine.decrypt(enc_mean)
    dec_time = (time.perf_counter() - t0) * 1000

    actual_total = sum(salaries)
    actual_mean = actual_total / n_count

    match_sum = abs(actual_total - decrypted_total) < 0.01
    match_mean = abs(actual_mean - decrypted_mean) < 0.1

    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("Decrypted Total", f"${decrypted_total:,.2f}", delta=f"Actual: ${actual_total:,.2f}")
    with m2:
        st.metric("Decrypted Mean", f"${decrypted_mean:,.2f}", delta=f"Actual: ${actual_mean:,.2f}")
    with m3:
        st.metric("Evaluator Execution Time", f"{agg_time:.2f} ms")

    if match_sum and match_mean:
        st.markdown("""
        <div class="he-card-success" style="margin-top: 15px;">
            <strong style="color: #3fb950;">Protocol Verification Successful:</strong>
            The decrypted aggregate sum and mean match the raw plaintext calculation exactly. 
            Individual salaries remained computationally unrecoverable to the evaluator.
        </div>
        """, unsafe_allow_html=True)
    else:
        st.error("Protocol verification failed: homomorphic evaluation produced numerical divergence.")

    # Benchmark summary
    st.markdown("---")
    b1, b2, b3 = st.columns(3)
    with b1:
        st.caption(f"Average Encryption: {sum(enc_times) / len(enc_times):.2f} ms")
    with b2:
        st.caption(f"Server Evaluation: {agg_time:.2f} ms")
    with b3:
        st.caption(f"Decryption Time: {dec_time:.2f} ms")

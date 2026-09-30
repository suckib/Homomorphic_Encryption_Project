"""
UI and styling utilities for the Homomorphic Encryption workbench.
"""

from typing import List, Tuple


def get_custom_css() -> str:
    """Return clean, modern dark styling for Streamlit."""
    return """
    <style>
        .stApp {
            background-color: #0f141c;
            color: #d8e1ec;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        h1, h2, h3, h4 {
            color: #e6edf3 !important;
            font-weight: 600 !important;
            letter-spacing: -0.02em;
        }

        .he-card {
            background-color: #161f2e;
            border: 1px solid #253347;
            border-radius: 8px;
            padding: 1.1rem 1.3rem;
            margin: 0.6rem 0;
        }

        .he-card-success {
            background-color: #12241d;
            border: 1px solid #23533c;
            border-radius: 8px;
            padding: 1.1rem 1.3rem;
            margin: 0.6rem 0;
        }

        .he-card-warning {
            background-color: #272213;
            border: 1px solid #584c20;
            border-radius: 8px;
            padding: 1.1rem 1.3rem;
            margin: 0.6rem 0;
        }

        .pipeline-container {
            display: flex;
            align-items: center;
            justify-content: center;
            flex-wrap: wrap;
            gap: 8px;
            padding: 14px 8px;
            background-color: #131b26;
            border: 1px solid #212d3d;
            border-radius: 8px;
            margin: 12px 0;
        }

        .pipeline-step {
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 500;
            color: #ffffff;
            transition: all 0.2s ease;
        }

        .pipeline-arrow {
            color: #586b84;
            font-size: 1rem;
            font-weight: 600;
        }

        .ciphertext-box {
            background-color: #0c1219;
            border: 1px solid #1f2b3b;
            border-radius: 6px;
            padding: 8px 12px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.78rem;
            color: #79c0ff;
            word-break: break-all;
            max-height: 85px;
            overflow-y: auto;
        }

        .stMetric {
            background-color: #161f2e;
            border: 1px solid #253347;
            border-radius: 6px;
            padding: 10px;
        }

        /* Suppress default Streamlit page footer */
        footer {
            display: none !important;
            visibility: hidden !important;
        }

        /* Suppress 'Made with Streamlit' branding in menu and popovers */
        [data-testid="stMainMenuPopover"] div:has(a[href*="streamlit.io"]),
        [data-testid="stMainMenuPopover"] hr:last-of-type,
        div[role="dialog"] div:has(a[href*="streamlit.io"]),
        div[role="dialog"] hr:last-of-type,
        a[href*="streamlit.io"],
        div:has(> a[href*="streamlit.io"]),
        span:has(> a[href*="streamlit.io"]) {
            display: none !important;
            visibility: hidden !important;
        }

        /* Suppress Deploy button in header */
        [data-testid="stToolbarActions"],
        .stDeployButton,
        [data-testid="stDeployButton"] {
            display: none !important;
            visibility: hidden !important;
        }
    </style>
    """


def pipeline_html(steps: List[Tuple[str, str]], active_step: int = -1) -> str:
    """Renders a simple flow diagram of execution stages."""
    stage_colors = {
        "plaintext": "#2da44e",
        "encrypt": "#d29922",
        "compute": "#1f6feb",
        "decrypt": "#8957e5",
        "result": "#2da44e"
    }

    elements = ['<div class="pipeline-container">']
    for idx, (label, stype) in enumerate(steps):
        bg = stage_colors.get(stype, "#57606a")
        opacity = "1.0" if (idx <= active_step or active_step == -1) else "0.35"
        elements.append(
            f'<span class="pipeline-step" style="background-color: {bg}; opacity: {opacity};">'
            f'{label}'
            f'</span>'
        )
        if idx < len(steps) - 1:
            elements.append('<span class="pipeline-arrow">&rarr;</span>')
    elements.append('</div>')
    return "".join(elements)


def comparison_card(title: str, plaintext_val, decrypted_val, match: bool) -> str:
    status_color = "#3fb950" if match else "#f85149"
    status_text = "Verified: Decrypted result equals plaintext computation" if match else "Discrepancy detected"

    return f"""
    <div class="he-card">
        <h4 style="margin: 0 0 12px 0; color: #79c0ff;">{title}</h4>
        <div style="display: flex; justify-content: space-around; align-items: center; margin: 10px 0;">
            <div style="text-align: center;">
                <div style="color: #8b949e; font-size: 0.8rem; margin-bottom: 4px;">Plaintext calculation</div>
                <div style="font-size: 1.6rem; font-weight: 600; color: #e6edf3;">{plaintext_val}</div>
            </div>
            <div style="font-size: 1.2rem; color: #484f58;">&harr;</div>
            <div style="text-align: center;">
                <div style="color: #8b949e; font-size: 0.8rem; margin-bottom: 4px;">Decrypted from ciphertext</div>
                <div style="font-size: 1.6rem; font-weight: 600; color: #79c0ff;">{decrypted_val}</div>
            </div>
        </div>
        <div style="text-align: center; margin-top: 10px; color: {status_color}; font-size: 0.9rem; font-weight: 500;">
            {status_text}
        </div>
    </div>
    """


def timing_card(encrypt_ms: float, compute_ms: float, decrypt_ms: float) -> str:
    total = encrypt_ms + compute_ms + decrypt_ms
    return f"""
    <div class="he-card">
        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.85rem; color: #8b949e;">
            <span>Encryption: <strong style="color: #d29922;">{encrypt_ms:.2f} ms</strong></span>
            <span>Homomorphic Op: <strong style="color: #58a6ff;">{compute_ms:.2f} ms</strong></span>
            <span>Decryption: <strong style="color: #bc8cff;">{decrypt_ms:.2f} ms</strong></span>
            <span>Total: <strong style="color: #3fb950;">{total:.2f} ms</strong></span>
        </div>
    </div>
    """

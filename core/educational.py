"""
Educational implementation of the Paillier cryptosystem.

Uses intentionally small primes so all modular arithmetic, intermediate
values, and verification steps can be inspected and computed manually.
"""

import math
import random
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any


@dataclass
class PaillierStep:
    step_number: int
    title: str
    description: str
    formula: str
    values: Dict[str, Any]
    result: Any


# Small primes suitable for manual inspection and demo arithmetic
CANDIDATE_PRIMES = [
    61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251
]


def L(x: int, n: int) -> int:
    """Paillier L-function: L(x) = (x - 1) // n"""
    return (x - 1) // n


def mod_inverse(a: int, m: int) -> int:
    """Extended Euclidean algorithm for modular inverse."""
    if math.gcd(a, m) != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) != 1")
    return pow(a, -1, m)


class EducationalPaillier:
    """
    Step-by-step Paillier implementation designed for educational inspection.
    """

    def __init__(self):
        self.p: int = 0
        self.q: int = 0
        self.n: int = 0
        self.n_sq: int = 0
        self.lam: int = 0
        self.g: int = 0
        self.mu: int = 0
        self.steps: List[PaillierStep] = []

    def _select_valid_primes(self) -> Tuple[int, int]:
        """
        Select p, q such that gcd(lcm(p-1, q-1), p*q) == 1.
        This prevents singular modular inverses when computing mu.
        """
        shuffled = CANDIDATE_PRIMES.copy()
        random.shuffle(shuffled)

        for i in range(len(shuffled)):
            for j in range(i + 1, len(shuffled)):
                p, q = shuffled[i], shuffled[j]
                n = p * q
                lam = math.lcm(p - 1, q - 1)
                # For g = n + 1, L(g^lambda mod n^2) == lambda mod n
                if math.gcd(lam, n) == 1:
                    return p, q

        # Fallback to guaranteed coprime pair
        return 61, 71

    def generate_keys(self) -> List[PaillierStep]:
        self.steps = []
        self.p, self.q = self._select_valid_primes()

        self.steps.append(PaillierStep(
            step_number=1,
            title="Prime Selection",
            description="Select two distinct primes p and q. Production keys typically use 1024 to 2048-bit primes.",
            formula=r"p, q \in \mathbb{P}",
            values={"p": self.p, "q": self.q},
            result=(self.p, self.q)
        ))

        # Modulus
        self.n = self.p * self.q
        self.n_sq = self.n * self.n

        self.steps.append(PaillierStep(
            step_number=2,
            title="Compute Modulus n and n²",
            description="n is the product of primes. Ciphertext operations occur modulo n².",
            formula=r"n = p \cdot q, \quad n^2 = n \cdot n",
            values={"n": self.n, "n²": self.n_sq},
            result=self.n
        ))

        # Carmichael's function lambda
        self.lam = math.lcm(self.p - 1, self.q - 1)

        self.steps.append(PaillierStep(
            step_number=3,
            title="Compute λ (Carmichael's totient)",
            description=r"λ = lcm(p - 1, q - 1), representing the order of the subgroup used for decryption.",
            formula=r"\lambda = \text{lcm}(p - 1, q - 1)",
            values={"p - 1": self.p - 1, "q - 1": self.q - 1, "λ": self.lam},
            result=self.lam
        ))

        # Generator g
        self.g = self.n + 1

        self.steps.append(PaillierStep(
            step_number=4,
            title="Select Base Generator g",
            description="Using the standard simplification g = n + 1, which ensures efficient encryption.",
            formula=r"g = n + 1",
            values={"g": self.g},
            result=self.g
        ))

        # Modular inverse mu
        g_lam = pow(self.g, self.lam, self.n_sq)
        l_val = L(g_lam, self.n)
        self.mu = mod_inverse(l_val, self.n)

        self.steps.append(PaillierStep(
            step_number=5,
            title="Compute Decryption Multiplier μ",
            description=r"μ is the modular inverse of L(g^λ mod n²) modulo n.",
            formula=r"\mu = \left( L(g^\lambda \bmod n^2) \right)^{-1} \bmod n",
            values={
                "g^λ mod n²": g_lam,
                "L(g^λ mod n²)": l_val,
                "μ": self.mu
            },
            result=self.mu
        ))

        return self.steps

    def encrypt_step_by_step(self, m: int) -> Tuple[int, List[PaillierStep]]:
        steps = []
        m_mod = m % self.n

        steps.append(PaillierStep(
            step_number=1,
            title="Plaintext Normalization",
            description=f"Ensure message m resides in the plaintext space [0, n - 1].",
            formula=r"m \in \mathbb{Z}_n",
            values={"m": m_mod, "n": self.n},
            result=m_mod
        ))

        # Pick random blinding factor r
        r = random.randint(2, self.n - 1)
        while math.gcd(r, self.n) != 1:
            r = random.randint(2, self.n - 1)

        steps.append(PaillierStep(
            step_number=2,
            title="Blinding Factor Selection",
            description="Choose random r coprime to n to provide semantic security (randomized encryption).",
            formula=r"r \xleftarrow{R} \mathbb{Z}_n^*, \quad \gcd(r, n) = 1",
            values={"r": r, "gcd(r, n)": math.gcd(r, self.n)},
            result=r
        ))

        g_m = pow(self.g, m_mod, self.n_sq)
        steps.append(PaillierStep(
            step_number=3,
            title="Compute Message Component",
            description="Raise generator g to plaintext power m modulo n².",
            formula=r"g^m \bmod n^2",
            values={"g^m mod n²": g_m},
            result=g_m
        ))

        r_n = pow(r, self.n, self.n_sq)
        steps.append(PaillierStep(
            step_number=4,
            title="Compute Blinding Component",
            description="Raise blinding factor r to power n modulo n².",
            formula=r"r^n \bmod n^2",
            values={"r^n mod n²": r_n},
            result=r_n
        ))

        c = (g_m * r_n) % self.n_sq
        steps.append(PaillierStep(
            step_number=5,
            title="Ciphertext Assembly",
            description="Multiply both components modulo n² to produce the final ciphertext c.",
            formula=r"c = g^m \cdot r^n \bmod n^2",
            values={"c": c},
            result=c
        ))

        return c, steps

    def decrypt_step_by_step(self, c: int) -> Tuple[int, List[PaillierStep]]:
        steps = []

        steps.append(PaillierStep(
            step_number=1,
            title="Ciphertext Input",
            description="Receive ciphertext c to decrypt with private parameters (λ, μ).",
            formula=r"c \in \mathbb{Z}_{n^2}^*",
            values={"c": c},
            result=c
        ))

        c_lam = pow(c, self.lam, self.n_sq)
        steps.append(PaillierStep(
            step_number=2,
            title="Exponentiation by λ",
            description="Compute c^λ modulo n².",
            formula=r"c^\lambda \bmod n^2",
            values={"c^λ mod n²": c_lam},
            result=c_lam
        ))

        l_val = L(c_lam, self.n)
        steps.append(PaillierStep(
            step_number=3,
            title="Evaluate L-Function",
            description="Apply quotient extraction L(u) = (u - 1) // n.",
            formula=r"L(c^\lambda \bmod n^2) = \frac{(c^\lambda \bmod n^2) - 1}{n}",
            values={"L value": l_val},
            result=l_val
        ))

        m = (l_val * self.mu) % self.n
        steps.append(PaillierStep(
            step_number=4,
            title="Message Recovery",
            description="Multiply by μ modulo n to isolate plaintext m.",
            formula=r"m = L(c^\lambda \bmod n^2) \cdot \mu \bmod n",
            values={"Recovered plaintext m": m},
            result=m
        ))

        return m, steps

    def homomorphic_add_step_by_step(self, c1: int, c2: int) -> Tuple[int, List[PaillierStep]]:
        steps = []

        steps.append(PaillierStep(
            step_number=1,
            title="Input Ciphertexts",
            description="Two ciphertexts c₁ and c₂ corresponding to plaintexts m₁ and m₂.",
            formula=r"c_1 = \text{Enc}(m_1), \quad c_2 = \text{Enc}(m_2)",
            values={"c₁": c1, "c₂": c2},
            result=(c1, c2)
        ))

        c_sum = (c1 * c2) % self.n_sq
        steps.append(PaillierStep(
            step_number=2,
            title="Modular Multiplication",
            description="Multiplying ciphertexts mod n² yields the ciphertext of the plaintext sum: Enc(m₁) · Enc(m₂) = Enc(m₁ + m₂).",
            formula=r"c_{\text{sum}} = c_1 \cdot c_2 \bmod n^2",
            values={"c_sum": c_sum},
            result=c_sum
        ))

        return c_sum, steps

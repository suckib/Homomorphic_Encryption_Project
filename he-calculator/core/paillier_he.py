"""
Paillier cryptosystem engine using python-paillier.

Supported operations:
- Additive homomorphism: Enc(m1) + Enc(m2) = Enc(m1 + m2)
- Subtraction: Enc(m1) - Enc(m2) = Enc(m1 - m2)
- Scalar multiplication: Enc(m1) * k = Enc(m1 * k) (where k is a plaintext scalar)
"""

import time
from dataclasses import dataclass
from typing import Optional, List
import phe.paillier as paillier


@dataclass
class PaillierResult:
    plaintext_a: float
    plaintext_b: float
    operation: str
    plaintext_result: float
    decrypted_result: float
    ciphertext_a_snippet: str
    ciphertext_b_snippet: str
    ciphertext_result_snippet: str
    encrypt_time_ms: float
    compute_time_ms: float
    decrypt_time_ms: float
    key_size_bits: int
    match: bool


class PaillierEngine:
    def __init__(self, key_length: int = 1024):
        self.key_length = key_length
        self.public_key: Optional[paillier.PaillierPublicKey] = None
        self.private_key: Optional[paillier.PaillierPrivateKey] = None
        self._generate_keys()

    def _generate_keys(self):
        self.public_key, self.private_key = paillier.generate_paillier_keypair(
            n_length=self.key_length
        )

    def encrypt(self, value: float) -> paillier.EncryptedNumber:
        return self.public_key.encrypt(value)

    def decrypt(self, encrypted: paillier.EncryptedNumber) -> float:
        return self.private_key.decrypt(encrypted)

    def ciphertext_snippet(self, encrypted: paillier.EncryptedNumber, length: int = 60) -> str:
        raw = str(encrypted.ciphertext())
        return raw[:length] + "..." if len(raw) > length else raw

    def compute(self, a: float, b: float, operation: str = "add") -> PaillierResult:
        # Encryption
        t0 = time.perf_counter()
        enc_a = self.encrypt(a)
        enc_b = self.encrypt(b) if operation != "multiply" else None
        encrypt_time = (time.perf_counter() - t0) * 1000

        # Homomorphic evaluation
        t1 = time.perf_counter()
        if operation == "add":
            enc_result = enc_a + enc_b
            plaintext_result = a + b
            op_symbol = "+"
        elif operation == "subtract":
            enc_result = enc_a - enc_b
            plaintext_result = a - b
            op_symbol = "-"
        elif operation == "multiply":
            # Note: b is treated as a plaintext scalar
            enc_result = enc_a * b
            plaintext_result = a * b
            op_symbol = "×"
        else:
            raise ValueError(f"Unsupported operation: {operation}")
        compute_time = (time.perf_counter() - t1) * 1000

        # Decryption
        t2 = time.perf_counter()
        decrypted_val = self.decrypt(enc_result)
        decrypt_time = (time.perf_counter() - t2) * 1000

        return PaillierResult(
            plaintext_a=a,
            plaintext_b=b,
            operation=f"{a} {op_symbol} {b}",
            plaintext_result=plaintext_result,
            decrypted_result=round(decrypted_val, 6),
            ciphertext_a_snippet=self.ciphertext_snippet(enc_a),
            ciphertext_b_snippet=self.ciphertext_snippet(enc_b) if enc_b else "(plaintext scalar)",
            ciphertext_result_snippet=self.ciphertext_snippet(enc_result),
            encrypt_time_ms=round(encrypt_time, 2),
            compute_time_ms=round(compute_time, 2),
            decrypt_time_ms=round(decrypt_time, 2),
            key_size_bits=self.key_length,
            match=abs(plaintext_result - decrypted_val) < 1e-4
        )

    def batch_encrypt(self, values: List[float]) -> List[paillier.EncryptedNumber]:
        return [self.encrypt(v) for v in values]

    def batch_sum(self, encrypted_values: List[paillier.EncryptedNumber]) -> paillier.EncryptedNumber:
        if not encrypted_values:
            return self.encrypt(0.0)
        total = encrypted_values[0]
        for item in encrypted_values[1:]:
            total = total + item
        return total

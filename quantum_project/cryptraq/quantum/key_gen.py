import secrets
import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
import logging

logger = logging.getLogger(__name__)

# Minimum acceptable sifted-key length.
# BB84 sifting discards ~50 % of bits on average (basis mismatch), so
# requesting n=32 qubits yields ~16 sifted bits on average.
MIN_KEY_BITS = 16


class QuantumSimulator:
    @staticmethod
    def generate_bb84_key(n: int = 64) -> str:
        """
        Simulates the BB84 QKD protocol using Qiskit Aer (qasm_simulator).

        SECURITY ASSUMPTIONS — MANDATORY DISCLOSURE FOR REVIEWERS:
        ──────────────────────────────────────────────────────────────
        1. CLASSICAL SIMULATION: This is a *simulation* of BB84, not true
           quantum hardware. The underlying randomness comes from numpy's
           Mersenne Twister PRNG, which is NOT a CSPRNG. It correctly models
           the quantum circuit mechanics but does not provide quantum entropy.

        2. NO EAVESDROPPER DETECTION: Real QKD measures the Quantum Bit Error
           Rate (QBER) to detect eavesdroppers. This simulation skips QBER
           entirely. An eavesdrop on the simulated channel is undetectable.

        3. NO INFORMATION RECONCILIATION / PRIVACY AMPLIFICATION: Real BB84
           includes error correction and PA to remove partial information an
           eavesdropper may have acquired. Neither is implemented here.

        4. VARIABLE OUTPUT LENGTH: Sifting discards mismatched-basis bits
           (~50 % on average). For n=64 qubits, expect ~32 sifted bits.
           The output is supplemented with secrets.token_hex() if the sifted
           result is shorter than MIN_KEY_BITS.

        5. KEY USE: The output feeds into SHA-256 in fernet_manager._derive_key().
           SHA-256 whitens the input, so partial PRNG predictability does not
           directly translate into a weak Fernet key — but this is a prototype
           assumption, not a production guarantee.

        In a production deployment, replace this module with a true QKD device
        API or a CSPRNG (secrets.token_hex) until quantum hardware is available.
        """
        try:
            sender_bits  = np.random.randint(2, size=n)
            sender_bases = np.random.randint(2, size=n)
            receiver_bases = np.random.randint(2, size=n)

            backend = Aer.get_backend("qasm_simulator")
            sifted = []

            for i in range(n):
                qc = QuantumCircuit(1, 1)
                if sender_bits[i]:   qc.x(0)
                if sender_bases[i]:  qc.h(0)
                if receiver_bases[i]: qc.h(0)
                qc.measure(0, 0)

                compiled = transpile(qc, backend)
                job = backend.run(compiled, shots=1)
                result = job.result()
                measured = int(list(result.get_counts().keys())[0])

                # Sift: keep bit only when bases match
                if sender_bases[i] == receiver_bases[i]:
                    sifted.append(str(measured))

            sifted_key = "".join(sifted)
            sifted_len = len(sifted_key)

            if sifted_len < MIN_KEY_BITS:
                # Supplement with CSPRNG output to meet minimum.
                # The supplement is prepended (not appended) so a length-0
                # sifted result still produces a strong key.
                supplement = secrets.token_hex(16)   # 128-bit CSPRNG output
                sifted_key = supplement + sifted_key
                logger.warning(
                    f"BB84 sifting yielded only {sifted_len} bits "
                    f"(requested {n}). Supplemented with 128-bit CSPRNG output. "
                    "See generate_bb84_key docstring for security assumptions."
                )

            logger.info(
                f"BB84 key generated: {sifted_len} sifted bits from {n} qubits "
                f"({sifted_len/n*100:.0f}% sift efficiency)."
            )
            return sifted_key

        except Exception as e:
            logger.error(f"Quantum simulation failed: {e}")
            raise Exception("Failed to generate quantum key.")

"""
JPEG-Robust Steganography Engine — CryptraQ
=============================================
Strategy: Block-Mean Comparison (BMC) steganography on the Blue channel.

Why it survives JPEG compression
---------------------------------
Standard LSB embedding is obliterated by JPEG's DCT quantisation. Instead,
we divide the image into pairs of adjacent 4x4 pixel blocks and encode each
bit by making one block's *mean* larger than the other by at least DELTA=30
intensity units.  JPEG compression shifts individual pixel values but
preserves block-average statistics well enough for DELTA=30 to survive at
quality ≥ 90.

Format
------
  MAGIC  (4 bytes: b"BMCS")
  LENGTH (4 bytes: big-endian uint32 — number of DATA bytes)
  DATA   (variable)

Capacity (default 800 × 800 cover, block_size=4)
-------------------------------------------------
  pairs_per_row = (800 // 4) // 2   = 100
  rows           = 800 // 4         = 200
  total_bits     = 100 × 200        = 20 000
  usable_bytes   = 20 000 // 8      = 2 500 bytes

Typical mission payload is ~800–1 400 bytes → fits comfortably.
"""

import numpy as np
from PIL import Image
import io

class SteganographyManager:
    MAGIC      = b"BMCS"
    BLOCK_SIZE = 4       # pixel block edge length
    DELTA      = 30      # minimum mean-difference required to survive JPEG Q≥90
    JPEG_QUALITY = 92    # quality for export (≥90 keeps DELTA intact)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def embed_data(img_array: np.ndarray, data: bytes) -> np.ndarray:
        """
        Embed *data* into *img_array* using Block-Mean Comparison on the
        Blue channel.  Returns a modified uint8 NumPy array of the same shape.
        Raises ValueError if the image is too small.
        """
        payload = (SteganographyManager.MAGIC
                   + len(data).to_bytes(4, 'big')
                   + data)
        bits    = ''.join(f"{b:08b}" for b in payload)

        capacity = SteganographyManager._bit_capacity(img_array)
        if len(bits) > capacity:
            raise ValueError(
                f"Image too small: need {len(bits)} bit-slots, "
                f"have {capacity}. Use a larger cover image."
            )

        return SteganographyManager._embed_bits(img_array.copy(), bits)

    @staticmethod
    def extract_data(img_array: np.ndarray) -> bytes | None:
        """
        Extract hidden data from *img_array*.  Returns None if no valid
        BMCS header is found (i.e. no payload was embedded, or wrong image).
        """
        bs    = SteganographyManager.BLOCK_SIZE
        magic = SteganographyManager.MAGIC

        # Read enough bits for MAGIC + LENGTH (8 bytes = 64 bits)
        header_bits = SteganographyManager._read_bits(img_array, 64)
        if len(header_bits) < 64:
            return None

        header_bytes = bytes(
            int(header_bits[i:i+8], 2) for i in range(0, 64, 8)
        )
        if header_bytes[:4] != magic:
            return None

        length     = int.from_bytes(header_bytes[4:8], 'big')
        total_bits = 64 + length * 8

        if SteganographyManager._bit_capacity(img_array) < total_bits:
            return None

        all_bits = SteganographyManager._read_bits(img_array, total_bits)
        data_bits = all_bits[64:]
        data = bytes(
            int(data_bits[i:i+8], 2) for i in range(0, length * 8, 8)
        )
        return data

    @staticmethod
    def create_default_cover(width: int = 800, height: int = 800) -> np.ndarray:
        """
        Generates a visually natural gradient cover image large enough to
        hold ~2 500 bytes of hidden payload after JPEG compression.
        """
        img = np.zeros((height, width, 3), dtype=np.uint8)
        for y in range(height):
            for x in range(width):
                img[y, x] = [
                    int(60  + 180 * x / width),
                    int(40  + 180 * y / height),
                    int(100 + 120 * (x + y) / (width + height)),
                ]
        return img

    @staticmethod
    def to_jpeg_bytes(img_array: np.ndarray,
                      quality: int = None) -> bytes:
        """
        Convert a NumPy RGB array to JPEG bytes at the standard quality.
        Use this to generate the downloadable file so sender and the extractor
        see the same post-compression image statistics.
        """
        if quality is None:
            quality = SteganographyManager.JPEG_QUALITY
        pil_img = Image.fromarray(img_array.astype(np.uint8))
        buf = io.BytesIO()
        pil_img.save(buf, format="JPEG", quality=quality,
                     subsampling=0)   # 4:4:4 preserves colour better
        return buf.getvalue()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _bit_capacity(img_array: np.ndarray) -> int:
        """How many bits can be embedded in this image."""
        H, W = img_array.shape[:2]
        bs   = SteganographyManager.BLOCK_SIZE
        pairs_per_row = (W // bs) // 2
        rows          = H // bs
        return pairs_per_row * rows

    @staticmethod
    def _embed_bits(img_array: np.ndarray, bits: str) -> np.ndarray:
        """Mutate img_array in-place (float32 headroom) and return uint8."""
        bs    = SteganographyManager.BLOCK_SIZE
        delta = SteganographyManager.DELTA
        H, W  = img_array.shape[:2]

        out = img_array.astype(np.float32)
        bit_idx = 0

        for y in range(0, H - bs + 1, bs):
            if bit_idx >= len(bits):
                break
            for x in range(0, W - 2 * bs + 1, 2 * bs):
                if bit_idx >= len(bits):
                    break

                ch = 2  # Blue channel
                A  = out[y:y+bs, x:x+bs,      ch]
                B  = out[y:y+bs, x+bs:x+2*bs, ch]

                meanA = float(np.mean(A))
                meanB = float(np.mean(B))

                bit = int(bits[bit_idx])
                if bit == 1:
                    # Enforce meanA - meanB >= delta
                    diff = meanA - meanB
                    if diff < delta:
                        shift = (delta - diff) / 2.0
                        out[y:y+bs, x:x+bs,      ch] += shift
                        out[y:y+bs, x+bs:x+2*bs, ch] -= shift
                else:
                    # Enforce meanB - meanA >= delta
                    diff = meanB - meanA
                    if diff < delta:
                        shift = (delta - diff) / 2.0
                        out[y:y+bs, x+bs:x+2*bs, ch] += shift
                        out[y:y+bs, x:x+bs,      ch] -= shift

                bit_idx += 1

        return np.clip(out, 0, 255).astype(np.uint8)

    @staticmethod
    def _read_bits(img_array: np.ndarray, n_bits: int) -> str:
        """Read exactly n_bits from the image block pairs."""
        bs   = SteganographyManager.BLOCK_SIZE
        H, W = img_array.shape[:2]
        bits = []

        for y in range(0, H - bs + 1, bs):
            if len(bits) >= n_bits:
                break
            for x in range(0, W - 2 * bs + 1, 2 * bs):
                if len(bits) >= n_bits:
                    break

                ch   = 2  # Blue channel
                A    = img_array[y:y+bs, x:x+bs,      ch]
                B    = img_array[y:y+bs, x+bs:x+2*bs, ch]
                meanA = float(np.mean(A))
                meanB = float(np.mean(B))

                bits.append("1" if meanA > meanB else "0")

        return "".join(bits)

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, Tuple

import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

DELIMITER = "#####END#####"


def _derive_aes128_key(secret: str) -> bytes:
    """Derive 16-byte key (AES-128) from passphrase."""
    return hashlib.sha256(secret.encode("utf-8")).digest()[:16]


def aes_encrypt(plaintext: str, passphrase: str = "secretkey") -> Dict[str, str]:
    """
    Encrypt plaintext using AES-128-CBC.
    Returns dict with base64 payload and metadata for display.
    """
    key = _derive_aes128_key(passphrase)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    payload = iv + ciphertext

    return {
        "algorithm": "AES-128",
        "mode": "CBC",
        "key_hex": key.hex().upper(),
        "iv_hex": iv.hex().upper(),
        "ciphertext_b64": base64.b64encode(payload).decode("utf-8"),
    }


def aes_decrypt(ciphertext_b64: str, passphrase: str = "secretkey") -> str:
    """Decrypt base64(iv+ciphertext) with AES-128-CBC."""
    key = _derive_aes128_key(passphrase)
    raw = base64.b64decode(ciphertext_b64)
    if len(raw) < 32:
        raise ValueError("Payload terenkripsi tidak valid.")
    iv, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode("utf-8")


def _text_to_binary(text: str) -> str:
    return "".join(format(byte, "08b") for byte in text.encode("utf-8"))


def _binary_to_text(binary_data: str) -> str:
    chunks = [binary_data[i : i + 8] for i in range(0, len(binary_data), 8)]
    data = bytes(int(chunk, 2) for chunk in chunks if len(chunk) == 8)
    return data.decode("utf-8", errors="ignore")


def lsb_embed(image_path: str, secret_text: str, output_path: str | None = None) -> str:
    """Embed secret text into image using 1-bit LSB on a SINGLE color channel.

    Perubahan dari versi sebelumnya:
    - Sebelumnya: 1-bit LSB ditanam ke SEMUA channel RGB (lebih banyak piksel berubah -> MSE cenderung naik).
    - Sekarang: 1-bit LSB ditanam hanya ke satu channel (mis. channel B karena OpenCV formatnya BGR).

    Hasil: perubahan citra lebih sedikit sehingga MSE biasanya lebih baik.
    """
    image = cv2.imread(image_path, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Gambar tidak ditemukan.")

    secret_text = secret_text + DELIMITER
    binary_data = _text_to_binary(secret_text)

    height, width, channels = image.shape
    if channels < 3:
        raise ValueError("Format gambar tidak sesuai (harus memiliki 3 channel BGR).")

    # OpenCV membaca dalam urutan BGR: channel 0=B, 1=G, 2=R
    target_channels = (0, 1, 2)

    # Kapasitas untuk 3 channel (1-bit per channel per piksel)
    max_capacity = height * width * len(target_channels)
    if len(binary_data) > max_capacity:
        raise ValueError("Pesan terlalu besar untuk gambar ini.")

    stego = image.copy()
    data_index = 0
    for row in range(height):
        for col in range(width):
            if data_index >= len(binary_data):
                break
            for ch in target_channels:
                if data_index >= len(binary_data):
                    break
                stego[row, col, ch] = (stego[row, col, ch] & 254) | int(binary_data[data_index])
                data_index += 1
            if data_index >= len(binary_data):
                break


    if output_path is None:
        timestamp = int(time.time())
        output_path = f"stego_{timestamp}.png"

    if not cv2.imwrite(output_path, stego):
        raise ValueError("Gagal menyimpan stego image.")

    return output_path



def lsb_extract(stego_image_path: str) -> str:
    """Extract embedded text payload from LSB image.

    Extract bit mengikuti urutan yang sama seperti `lsb_embed()`:
    iterasi piksel per baris, lalu untuk setiap piksel: channel B (0), G (1), R (2).
    """
    image = cv2.imread(stego_image_path, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Stego image tidak ditemukan.")

    height, width, channels = image.shape
    if channels < 3:
        raise ValueError("Format gambar tidak sesuai (harus memiliki 3 channel BGR).")

    target_channels = (0, 1, 2)

    bits = []
    for row in range(height):
        for col in range(width):
            for ch in target_channels:
                bits.append(str(image[row, col, ch] & 1))

    binary_data = "".join(bits)
    extracted_chars = []
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i : i + 8]
        if len(byte) < 8:
            break
        extracted_chars.append(chr(int(byte, 2)))
        text = "".join(extracted_chars)
        if DELIMITER in text:
            return text.split(DELIMITER)[0]

    raise ValueError("Delimiter tidak ditemukan. Data steganografi tidak valid.")



def process_secure_embedding(
    message: str,
    image_path: str,
    passphrase: str = "secretkey",
    output_path: str | None = None,
) -> Dict[str, str]:
    """
    Complete AES + LSB process.
    Returns metadata and output path for integration in GUI/CLI.
    """
    enc = aes_encrypt(message, passphrase)
    stego_path = lsb_embed(image_path, enc["ciphertext_b64"], output_path)
    return {
        "stego_path": stego_path,
        "algorithm": enc["algorithm"],
        "mode": enc["mode"],
        "key_hex": enc["key_hex"],
        "iv_hex": enc["iv_hex"],
        "ciphertext_b64": enc["ciphertext_b64"],
    }


if __name__ == "__main__":
    payload = process_secure_embedding(
        message="Ini pesan rahasia data medis",
        image_path="input.png",
        passphrase="contoh-kunci-kuat",
    )
    print(json.dumps(payload, indent=2))
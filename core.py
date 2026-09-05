import io
import math
import struct
from pathlib import Path
from typing import Dict, Tuple, Union

import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

MAGIC = b"STG1"
VERSION = 1

TYPE_TEXT = 1
TYPE_FILE = 2

SALT_LEN = 16
NONCE_LEN = 12
GCM_TAG_LEN = 16

KDF_ITERATIONS = 600_000

# Fixed header format
HEADER_FORMAT = ">4sBBH16s12sI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


# ============================================================
# Cryptography
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=32,
        count=KDF_ITERATIONS,
        hmac_hash_module=SHA256,
    )


def encrypt_data(data: bytes, password: str) -> Tuple[bytes, bytes, bytes]:
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes.")

    salt = get_random_bytes(SALT_LEN)
    nonce = get_random_bytes(NONCE_LEN)
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted_payload = ciphertext + tag

    return salt, nonce, encrypted_payload


def decrypt_data(ciphertext: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
    if len(ciphertext) < GCM_TAG_LEN:
        raise ValueError("Encrypted payload is too short.")
    if len(salt) != SALT_LEN:
        raise ValueError("Invalid salt length.")
    if len(nonce) != NONCE_LEN:
        raise ValueError("Invalid nonce length.")

    key = derive_key(password, salt)
    encrypted_data = ciphertext[:-GCM_TAG_LEN]
    tag = ciphertext[-GCM_TAG_LEN:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(encrypted_data, tag)
    except ValueError as exc:
        raise ValueError(
            "Authentication failed. The password may be incorrect or the payload is corrupted."
        ) from exc

    return plaintext


# ============================================================
# Payload formatting
# ============================================================

def build_payload(data: bytes, password: str, payload_type: int, filename: str = "") -> bytes:
    if payload_type not in (TYPE_TEXT, TYPE_FILE):
        raise ValueError("Unsupported payload type.")

    filename_bytes = filename.encode("utf-8")
    if len(filename_bytes) > 65535:
        raise ValueError("Filename is too long.")

    salt, nonce, ciphertext = encrypt_data(data, password)
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        VERSION,
        payload_type,
        len(filename_bytes),
        salt,
        nonce,
        len(ciphertext),
    )
    return header + filename_bytes + ciphertext


def parse_header(header: bytes) -> dict:
    if len(header) != HEADER_SIZE:
        raise ValueError("Invalid header length.")

    (
        magic,
        version,
        payload_type,
        filename_len,
        salt,
        nonce,
        ciphertext_len,
    ) = struct.unpack(HEADER_FORMAT, header)

    if magic != MAGIC:
        raise ValueError("No valid steganography payload was found.")
    if version != VERSION:
        raise ValueError(f"Unsupported payload version: {version}")
    if payload_type not in (TYPE_TEXT, TYPE_FILE):
        raise ValueError("Unsupported payload type.")
    if ciphertext_len < GCM_TAG_LEN:
        raise ValueError("Invalid encrypted payload length.")

    return {
        "payload_type": payload_type,
        "filename_len": filename_len,
        "salt": salt,
        "nonce": nonce,
        "ciphertext_len": ciphertext_len,
    }


# ============================================================
# LSB Operations
# ============================================================

def image_capacity_bytes(image: Image.Image) -> int:
    rgb = image.convert("RGB")
    width, height = rgb.size
    total_channels = width * height * 3
    return total_channels // 8


def bytes_to_bits(data: bytes):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def bits_to_bytes(bits) -> bytes:
    output = bytearray()
    value = 0
    count = 0
    for bit in bits:
        value = (value << 1) | int(bit)
        count += 1
        if count == 8:
            output.append(value)
            value = 0
            count = 0
    if count != 0:
        raise ValueError("Incomplete byte sequence.")
    return bytes(output)


def embed_payload(image: Image.Image, payload: bytes) -> Image.Image:
    rgb = image.convert("RGB")
    array = np.array(rgb, dtype=np.uint8, copy=True)
    flat = array.reshape(-1)

    required_bits = len(payload) * 8
    if required_bits > flat.size:
        capacity = flat.size // 8
        raise ValueError(f"Payload too large. Required: {len(payload):,} bytes, Capacity: {capacity:,} bytes")

    for index, bit in enumerate(bytes_to_bits(payload)):
        flat[index] = (flat[index] & 0xFE) | bit

    return Image.fromarray(array, mode="RGB")


def extract_bytes(image: Image.Image, num_bytes: int) -> bytes:
    if num_bytes < 0:
        raise ValueError("Number of bytes cannot be negative.")

    rgb = image.convert("RGB")
    array = np.asarray(rgb, dtype=np.uint8)
    flat = array.reshape(-1)

    required_bits = num_bytes * 8
    if required_bits > flat.size:
        raise ValueError("Requested payload exceeds image capacity.")

    bits = [int(flat[i] & 1) for i in range(required_bits)]
    return bits_to_bytes(bits)


def extract_payload(image: Image.Image) -> Tuple[bytes, dict]:
    header = extract_bytes(image, HEADER_SIZE)
    meta = parse_header(header)

    total_size = HEADER_SIZE + meta["filename_len"] + meta["ciphertext_len"]
    capacity = image_capacity_bytes(image)

    if total_size > capacity:
        raise ValueError("Payload metadata specifies an invalid payload size.")

    payload = extract_bytes(image, total_size)
    return payload, meta


def decode_payload(payload: bytes, meta: dict, password: str) -> Tuple[bytes, str]:
    filename_start = HEADER_SIZE
    filename_end = filename_start + meta["filename_len"]
    ciphertext_end = filename_end + meta["ciphertext_len"]

    if ciphertext_end != len(payload):
        raise ValueError("Payload length is inconsistent or corrupted.")

    filename_bytes = payload[filename_start:filename_end]
    ciphertext = payload[filename_end:ciphertext_end]

    try:
        filename = filename_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Payload filename metadata is corrupted.") from exc

    plaintext = decrypt_data(ciphertext, password, meta["salt"], meta["nonce"])
    return plaintext, filename


# ============================================================
# Quality Metrics
# ============================================================

def calculate_mse(original: Image.Image, stego: Image.Image) -> float:
    a = np.asarray(original.convert("RGB"), dtype=np.float64)
    b = np.asarray(stego.convert("RGB"), dtype=np.float64)
    if a.shape != b.shape:
        raise ValueError(f"Image dimensions mismatch: {a.shape} vs {b.shape}")
    return float(np.mean((a - b) ** 2))


def calculate_psnr(mse: float) -> float:
    if mse == 0:
        return float("inf")
    return 10.0 * math.log10((255.0 ** 2) / mse)


def calculate_lsb_balance(image: Image.Image) -> float:
    array = np.asarray(image.convert("RGB"), dtype=np.uint8)
    lsb_ones = np.count_nonzero(array & 1)
    total = array.size
    return 0.0 if total == 0 else 100.0 * lsb_ones / total
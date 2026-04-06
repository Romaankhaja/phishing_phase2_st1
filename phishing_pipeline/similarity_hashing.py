import hashlib
import re
from collections import Counter
from io import BytesIO
from typing import Iterable

from PIL import Image

try:
    import imagehash
except Exception:  # pragma: no cover - dependency should exist, but fail safely
    imagehash = None


SIMHASH_BITS = 64
SIMHASH_HEX_LEN = SIMHASH_BITS // 4


def _normalize_hex_hash(value) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if text.startswith("0x"):
        text = text[2:]
    return text


def hamming_distance(hash1, hash2, *, hash_bits: int = SIMHASH_BITS) -> int | None:
    left = _normalize_hex_hash(hash1)
    right = _normalize_hex_hash(hash2)
    if not left or not right:
        return None
    try:
        left_int = int(left, 16)
        right_int = int(right, 16)
    except (TypeError, ValueError):
        return None
    return int((left_int ^ right_int).bit_count())


def normalized_hamming_similarity(hash1, hash2, *, hash_bits: int = SIMHASH_BITS) -> float:
    distance = hamming_distance(hash1, hash2, hash_bits=hash_bits)
    if distance is None:
        return 0.0
    return max(0.0, 1.0 - (float(distance) / float(hash_bits)))


def best_similarity_against_set(candidate_hash, reference_hashes: Iterable, *, hash_bits: int = SIMHASH_BITS) -> tuple[float, int | None]:
    candidate = _normalize_hex_hash(candidate_hash)
    if not candidate:
        return 0.0, None

    best_similarity = 0.0
    best_distance = None
    for reference in reference_hashes or ():
        distance = hamming_distance(candidate, reference, hash_bits=hash_bits)
        if distance is None:
            continue
        similarity = max(0.0, 1.0 - (float(distance) / float(hash_bits)))
        if similarity > best_similarity or (similarity == best_similarity and (best_distance is None or distance < best_distance)):
            best_similarity = similarity
            best_distance = distance
    return best_similarity, best_distance


def compute_image_phash(image_source, *, hash_size: int = 8) -> str | None:
    if imagehash is None or image_source in (None, b"", ""):
        return None
    try:
        if isinstance(image_source, Image.Image):
            image = image_source.copy()
        elif isinstance(image_source, (bytes, bytearray)):
            image = Image.open(BytesIO(image_source))
        else:
            image = Image.open(image_source)
        with image:
            rgb = image.convert("RGB")
            return str(imagehash.phash(rgb, hash_size=hash_size))
    except Exception:
        return None


def _coerce_features(text: str, *, mode: str) -> Counter:
    normalized = str(text or "").strip().lower()
    if not normalized:
        return Counter()
    if mode == "char3":
        padded = f"^{normalized}$"
        if len(padded) < 3:
            return Counter({padded: 1})
        return Counter(padded[i : i + 3] for i in range(len(padded) - 2))
    if mode == "char5":
        padded = f"^{normalized}$"
        if len(padded) < 5:
            return Counter({padded: 1})
        return Counter(padded[i : i + 5] for i in range(len(padded) - 4))
    return Counter(re.findall(r"[a-z0-9]+", normalized))


def compute_simhash(text: str, *, hash_bits: int = SIMHASH_BITS, mode: str = "word") -> str | None:
    features = _coerce_features(text, mode=mode)
    if not features:
        return None

    accum = [0] * hash_bits
    for feature, weight in features.items():
        digest = hashlib.sha256(feature.encode("utf-8")).digest()
        digest_int = int.from_bytes(digest[: hash_bits // 8], byteorder="big", signed=False)
        for bit_index in range(hash_bits):
            bit_mask = 1 << (hash_bits - 1 - bit_index)
            accum[bit_index] += int(weight) if (digest_int & bit_mask) else -int(weight)

    result = 0
    for value in accum:
        result = (result << 1) | (1 if value >= 0 else 0)
    return f"{result:0{hash_bits // 4}x}"


def normalize_domain_for_simhash(domain: str) -> str:
    text = str(domain or "").strip().lower()
    if not text:
        return ""
    return re.sub(r"[^a-z0-9.-]+", "", text)


def compute_domain_simhash(domain: str, *, hash_bits: int = SIMHASH_BITS) -> str | None:
    normalized = normalize_domain_for_simhash(domain)
    if not normalized:
        return None
    return compute_simhash(normalized, hash_bits=hash_bits, mode="char3")


def _extract_cert_name_values(name_entries) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for rdn in name_entries or ():
        for key, value in rdn:
            key_text = str(key or "").strip().lower()
            value_text = str(value or "").strip().lower()
            if not key_text or not value_text:
                continue
            output.setdefault(key_text, []).append(value_text)
    return output


def canonicalize_ssl_identity(cert_dict: dict | None) -> str:
    cert_dict = cert_dict or {}
    subject = _extract_cert_name_values(cert_dict.get("subject"))
    issuer = _extract_cert_name_values(cert_dict.get("issuer"))
    sans = sorted(
        {
            str(value or "").strip().lower()
            for entry_type, value in cert_dict.get("subjectAltName", []) or []
            if str(entry_type or "").strip().upper() == "DNS" and str(value or "").strip()
        }
    )
    parts = []
    for label, values in (
        ("subject_cn", subject.get("commonname", [])),
        ("subject_o", subject.get("organizationname", [])),
        ("issuer_cn", issuer.get("commonname", [])),
        ("issuer_o", issuer.get("organizationname", [])),
    ):
        if values:
            parts.append(f"{label}={'|'.join(sorted(set(values)))}")
    if sans:
        parts.append(f"san={'|'.join(sans)}")
    return "||".join(parts)


def compute_ssl_simhash(cert_dict: dict | None, *, hash_bits: int = SIMHASH_BITS) -> str | None:
    canonical = canonicalize_ssl_identity(cert_dict)
    if not canonical:
        return None
    return compute_simhash(canonical, hash_bits=hash_bits, mode="word")

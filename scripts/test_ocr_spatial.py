"""
test_ocr_spatial.py — Smoke test for OCR spatial zone features + TVC.

Tests:
  1. extract_spatial_ocr_features() with mock bounding box data
  2. extract_tvc_features() spoofing + legitimate detection
  3. run_ocr_inference() return type validation

Usage:
    cd c:\\Users\\SATWIK\\Documents\\Phishing
    python -m scripts.test_ocr_spatial
"""

import sys
import os

# Ensure project root is on the path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, ROOT_DIR)

import numpy as np


def test_spatial_features():
    """Test extract_spatial_ocr_features with synthetic bounding box data."""
    from phishing_pipeline.visual_features import extract_spatial_ocr_features

    # Simulate a 900-pixel tall image
    img_np = np.ones((900, 1280), dtype=np.uint8) * 255

    # Mock OCR results: (bbox, text, confidence)
    # Header zone (top 20% = y < 180): brand text
    # Body zone (20%–80% = 180 < y < 720): form text
    # Footer zone (bottom 20% = y > 720): legal text
    mock_results = [
        ([[10, 50], [200, 50], [200, 80], [10, 80]], "SBI Bank", 0.95),        # Header
        ([[10, 100], [300, 100], [300, 130], [10, 130]], "Internet Banking", 0.92),  # Header
        ([[10, 400], [400, 400], [400, 430], [10, 430]], "Enter Username", 0.88),  # Body
        ([[10, 450], [400, 450], [400, 480], [10, 480]], "Enter Password", 0.90),  # Body
        ([[10, 750], [500, 750], [500, 780], [10, 780]], "Copyright 2024 SBI", 0.85),  # Footer
    ]

    feats = extract_spatial_ocr_features(img_np, mock_results)

    assert "SBI Bank" in feats["ocr_header_text"], f"Expected SBI in header, got: {feats['ocr_header_text']}"
    assert "Enter Username" in feats["ocr_body_text"], f"Expected form text in body, got: {feats['ocr_body_text']}"
    assert "Copyright" in feats["ocr_footer_text"], f"Expected copyright in footer, got: {feats['ocr_footer_text']}"
    assert feats["ocr_header_word_count"] == 2, f"Expected 2 header items, got {feats['ocr_header_word_count']}"
    assert feats["ocr_footer_word_count"] == 1, f"Expected 1 footer item, got {feats['ocr_footer_word_count']}"
    assert feats["ocr_total_word_count"] == 5, f"Expected 5 total, got {feats['ocr_total_word_count']}"

    print("✅ test_spatial_features PASSED")
    print(f"   Header: {feats['ocr_header_text']}")
    print(f"   Body:   {feats['ocr_body_text']}")
    print(f"   Footer: {feats['ocr_footer_text']}")
    return feats


def test_tvc_features():
    """Test extract_tvc_features for spoofing detection."""
    from phishing_pipeline.utils import extract_tvc_features

    # Case 1: Brand spoofed — SBI text on non-SBI domain
    r1 = extract_tvc_features("http://sbi-login.xyz", "State Bank of India SBI Login", "")
    assert r1["tvc_brand_spoofed"] is True, f"Expected spoofed, got: {r1}"
    assert r1["tvc_detected_brand"] == "sbi", f"Expected brand=sbi, got: {r1['tvc_detected_brand']}"

    # Case 2: Legitimate — SBI text on actual SBI domain
    r2 = extract_tvc_features("https://onlinesbi.com", "State Bank of India SBI Login", "")
    assert r2["tvc_domain_match"] is True, f"Expected match, got: {r2}"
    assert r2["tvc_brand_spoofed"] is False, f"Expected not spoofed, got: {r2}"

    # Case 3: No brand detected
    r3 = extract_tvc_features("https://example.com", "Welcome to our site", "")
    assert r3["tvc_brand_detected"] is False, f"Expected no brand, got: {r3}"

    # Case 4: Brand in footer (copyright)
    r4 = extract_tvc_features("http://secure-pay.xyz", "", "Copyright 2024 ICICI Bank Ltd")
    assert r4["tvc_brand_spoofed"] is True, f"Expected spoofed via footer, got: {r4}"
    assert r4["tvc_detected_brand"] == "icici", f"Expected icici, got: {r4['tvc_detected_brand']}"

    print("✅ test_tvc_features PASSED")
    print(f"   Spoofed:  {r1}")
    print(f"   Legit:    {r2}")
    print(f"   NoBrand:  {r3}")
    print(f"   Footer:   {r4}")


def test_ocr_return_type():
    """Test run_ocr_inference returns (str, list) tuple."""
    from phishing_pipeline.visual_features import run_ocr_inference

    # Blank white image — no text expected
    dummy = np.ones((200, 400), dtype=np.uint8) * 255
    result = run_ocr_inference(dummy)

    assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
    text, raw = result
    assert isinstance(text, str), f"text must be str, got {type(text)}"
    assert isinstance(raw, list), f"raw must be list, got {type(raw)}"

    # None input
    text2, raw2 = run_ocr_inference(None)
    assert text2 == "", f"Expected empty text for None input, got {repr(text2)}"
    assert raw2 == [], f"Expected empty list for None input, got {raw2}"

    print("✅ test_ocr_return_type PASSED")
    print(f"   Blank image: text={repr(text)}, raw_len={len(raw)}")


if __name__ == "__main__":
    print("=" * 60)
    print("🧪 OCR Spatial + TVC Feature Smoke Tests")
    print("=" * 60)

    print("\n--- Test 1: Spatial OCR zones ---")
    test_spatial_features()

    print("\n--- Test 2: TVC features ---")
    test_tvc_features()

    print("\n--- Test 3: OCR return type ---")
    test_ocr_return_type()

    print("\n" + "=" * 60)
    print("🎉 ALL TESTS PASSED")
    print("=" * 60)

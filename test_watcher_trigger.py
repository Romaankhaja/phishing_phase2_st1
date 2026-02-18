"""
Test script: creates a dummy .xlsx upload in today's date folder
inside PHISHING_INPUTS to verify that the watcher triggers the pipeline.
"""
import os
from datetime import datetime
import pandas as pd

INPUT_DIR = r"C:\Users\SATWIK\Documents\PHISHING_UPLOADS\PHISHING_INPUTS"
TODAY     = datetime.now().strftime("%Y-%m-%d")
FOLDER    = os.path.join(INPUT_DIR, TODAY)

def main():
    os.makedirs(FOLDER, exist_ok=True)

    test_urls = [
        "onlinesbi-update.com",
        "hdfc-netbanking-verify.com",
        "icici-kyc-alert.net",
        "irctc-ticket-booking.org",
        "airtel-payment-link.xyz",
        "jio-recharge-offer.online",
        "amazon-fake-delivery.com",
        "google-security-check.net",
        "facebook-login-secure.com",
        "netflix-payment-failed.com",
    ]

    filepath = os.path.join(FOLDER, "test_domains.xlsx")
    pd.DataFrame({"URL": test_urls}).to_excel(filepath, index=False)

    print(f"✅  Created {filepath}  ({len(test_urls)} URLs)")
    print(f"    Folder: {FOLDER}")
    print()
    print("Now start the watcher in another terminal:")
    print(f"    python phishing_pipeline\\watcher.py")

if __name__ == "__main__":
    main()

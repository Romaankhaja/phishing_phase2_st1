"""
Download a file from a OneDrive / SharePoint share link and save it to data/holdout_sets/.

Supports both:
  - Consumer  OneDrive links  (1drv.ms, onedrive.live.com)
  - Corporate SharePoint links (*.sharepoint.com)

Usage:
    python download_from_onedrive.py "<SHARE_LINK>"
    python download_from_onedrive.py "<SHARE_LINK>" --filename custom_name.xlsx
"""

import sys
import os
import base64
import re
import urllib.parse
import requests

SAVE_DIR = os.path.join(os.path.dirname(__file__), "data", "holdout_sets")


def _is_sharepoint_link(url: str) -> bool:
    """Return True if *url* points to a SharePoint-hosted OneDrive."""
    return "sharepoint.com" in url.lower()


def _sharepoint_to_download_url(share_link: str) -> str:
    """Convert a SharePoint share link to a direct-download URL.

    SharePoint share links like:
        https://<tenant>-my.sharepoint.com/:x:/g/personal/<user>/<token>?e=<hash>
    can be turned into direct downloads by rewriting the path to use
    the download.aspx endpoint.
    """
    parsed = urllib.parse.urlparse(share_link)
    # Build the download URL using SharePoint's download.aspx trick
    # e.g.  /:x:/g/personal/user/TOKEN  ->  /personal/user/_layouts/15/download.aspx?share=TOKEN
    path_parts = parsed.path.strip("/").split("/")

    # Typical structure:  :x:  / g / personal / <user> / <token>
    # We need to extract the personal/<user> prefix and the token
    if len(path_parts) >= 5:
        # path_parts = [':x:', 'g', 'personal', '<user>', '<token>']
        user_path = "/".join(path_parts[2:4])  # personal/<user>
        token = path_parts[4]
        download_path = f"/{user_path}/_layouts/15/download.aspx"
        query = f"share={token}"
        download_url = f"{parsed.scheme}://{parsed.netloc}{download_path}?{query}"
        return download_url

    # Fallback: try appending download=1 to the original URL
    sep = "&" if "?" in share_link else "?"
    return f"{share_link}{sep}download=1"


def _onedrive_to_download_url(share_link: str) -> str:
    """Convert a consumer OneDrive share link to a direct download URL via the Graph API."""
    # https://learn.microsoft.com/en-us/graph/api/shares-get
    encoded = base64.urlsafe_b64encode(share_link.encode("utf-8")).decode("utf-8")
    share_token = "u!" + encoded.rstrip("=")
    return f"https://api.onedrive.com/v1.0/shares/{share_token}/root/content"


def share_to_download_url(share_link: str) -> str:
    """Route to the correct converter based on the link type."""
    if _is_sharepoint_link(share_link):
        return _sharepoint_to_download_url(share_link)
    return _onedrive_to_download_url(share_link)


def download_file(url: str, dest_path: str) -> None:
    """Stream-download a file from *url* and write it to *dest_path*."""
    print(f"Downloading -> {dest_path}")
    with requests.get(url, stream=True, allow_redirects=True, timeout=120) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        downloaded = 0
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded / total * 100
                    print(f"\r  {downloaded:,} / {total:,} bytes ({pct:.1f}%)", end="")
    print(f"\n[OK] Saved to {dest_path}  ({os.path.getsize(dest_path):,} bytes)")


def _infer_filename(url: str, share_link: str) -> str:
    """Try to figure out the filename from the HTTP response or the share link."""
    try:
        head = requests.head(url, allow_redirects=True, timeout=30)
        cd = head.headers.get("Content-Disposition", "")
        if "filename=" in cd:
            # Could be: filename="name.xlsx" or filename*=UTF-8''name.xlsx
            match = re.search(r'filename\*?=["\']?(?:UTF-8\'\')?([^"\';\r\n]+)', cd, re.IGNORECASE)
            if match:
                return urllib.parse.unquote(match.group(1).strip())
        # Fall back to the last path segment of the final URL
        parsed = urllib.parse.urlparse(head.url)
        basename = urllib.parse.unquote(os.path.basename(parsed.path))
        if basename and basename not in ("content", "download.aspx", ""):
            return basename
    except Exception as exc:
        print(f"  (Could not infer filename via HEAD: {exc})")

    # Last resort: try the original share link for hints
    parsed = urllib.parse.urlparse(share_link)
    basename = urllib.parse.unquote(os.path.basename(parsed.path))
    if basename and not basename.startswith(":"):
        return basename

    return "downloaded_file"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    share_link = sys.argv[1]

    # Optional: override the filename
    filename = None
    if "--filename" in sys.argv:
        idx = sys.argv.index("--filename")
        filename = sys.argv[idx + 1]

    # Build the direct-download URL
    download_url = share_to_download_url(share_link)
    print(f"Share link type: {'SharePoint' if _is_sharepoint_link(share_link) else 'OneDrive'}")
    print(f"Download URL:    {download_url}")

    # If no filename given, try to infer from the redirect or share link
    if not filename:
        filename = _infer_filename(download_url, share_link)

    print(f"Filename:        {filename}")

    os.makedirs(SAVE_DIR, exist_ok=True)
    dest = os.path.join(SAVE_DIR, filename)
    download_file(download_url, dest)


if __name__ == "__main__":
    main()

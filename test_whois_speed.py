"""
test_whois_speed.py — Standalone WHOIS/RDAP speed benchmark
============================================================
Tests the 3-pass parallel lookup strategy on 100 domains:
  Pass 0: DNS Pre-filter  (semaphore=20)
  Pass 1: RDAP Batch      (semaphore=4, direct to registries)
  Pass 2: WHOIS Fallback  (semaphore=2, rate-limited)

Usage:
    cd c:\\Users\\SATWIK\\Documents\\Phishing
    venv\\Scripts\\python.exe test_whois_speed.py
"""

import sys, os, asyncio, socket, time, logging

# Windows asyncio fix
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import httpx
import whois
import tldextract
import pandas as pd

# ── Configuration ──────────────────────────────────────────────────
HOLDOUT_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "PS-02_hold-out_Set_2",
    "newly-registered-domains-2026-01-15.xlsx",
)
NUM_DOMAINS = 1000

# Concurrency settings (matching utils.py)
MAX_CONCURRENT_RDAP = 20
MAX_CONCURRENT_WHOIS = 1
MAX_CONCURRENT_DNS_PREFILTER = 100

# Direct RDAP URLs (bypass rdap.org bootstrap)
RDAP_DIRECT_URLS = {
    # Verisign
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    # Identity Digital (Donuts/Afilias)
    "biz":  "https://rdap.identitydigital.services/rdap/domain/",
    "info": "https://rdap.identitydigital.services/rdap/domain/",
    "io":   "https://rdap.identitydigital.services/rdap/domain/",
    "mobi": "https://rdap.identitydigital.services/rdap/domain/",
    "pro":  "https://rdap.identitydigital.services/rdap/domain/",
    # CentralNic
    "xyz":    "https://rdap.centralnic.com/xyz/domain/",
    "top":    "https://rdap.centralnic.com/top/domain/",
    "lat":    "https://rdap.centralnic.com/lat/domain/",
    "online": "https://rdap.centralnic.com/online/domain/",
    "site":   "https://rdap.centralnic.com/site/domain/",
    "shop":   "https://rdap.centralnic.com/shop/domain/",
    "store":  "https://rdap.centralnic.com/store/domain/",
    "vip":    "https://rdap.centralnic.com/vip/domain/",
    # PIR (.org)
    "org": "https://rdap.org/domain/",
    # NIXI (.in)
    "in":  "https://rdap.registry.in/domain/",
}
RDAP_FALLBACK_URL = "https://rdap.org/domain/"

# Logging
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# ── RDAP Response Parser ──────────────────────────────────────────
def parse_rdap(data: dict) -> dict:
    """Parse raw RDAP JSON into {reg_date, registrar, registrant_name, registrant_country, name_servers}."""
    result = {
        "reg_date": "NA", "registrar": "NA", "registrant_name": "NA",
        "registrant_country": "NA", "name_servers": "NA",
    }
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            result["reg_date"] = event.get("eventDate", "NA")
            break
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [None, []])
        items = vcard[1] if len(vcard) > 1 else []
        fn = "NA"
        for item in items:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                fn = item[3]; break
        if "registrar" in roles and fn != "NA":
            result["registrar"] = fn
        if "registrant" in roles and fn != "NA":
            result["registrant_name"] = fn
    ns_list = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
    result["name_servers"] = ";".join(n for n in ns_list if n) or "NA"
    return result


def get_rdap_url(host):
    ext = tldextract.extract(host)
    tld = ext.suffix.split(".")[-1] if ext.suffix else ""
    return RDAP_DIRECT_URLS.get(tld, RDAP_FALLBACK_URL)


# ── Rate Limiter ──────────────────────────────────────────────────
class RateLimiter:
    def __init__(self, requests_per_minute=20):
        self.interval = 60.0 / requests_per_minute
        self.last = 0
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = time.time()
            elapsed = now - self.last
            if elapsed < self.interval:
                await asyncio.sleep(self.interval - elapsed)
            self.last = time.time()


# ── Main Benchmark ────────────────────────────────────────────────
async def benchmark():
    # ── Load domains ──
    print("=" * 70)
    print(f"⚡ WHOIS/RDAP Speed Benchmark — {NUM_DOMAINS} domains")
    print(f"📁 Source: {os.path.basename(HOLDOUT_FILE)}")
    print(f"🔧 Concurrency: DNS={MAX_CONCURRENT_DNS_PREFILTER}, RDAP={MAX_CONCURRENT_RDAP}, WHOIS={MAX_CONCURRENT_WHOIS}")
    print("=" * 70)

    df = pd.read_excel(HOLDOUT_FILE, nrows=NUM_DOMAINS)
    domains = df["Domain"].astype(str).str.strip().tolist()
    print(f"\n📋 Loaded {len(domains)} domains")

    # ── Timing trackers ──
    rdap_times = []
    whois_times = []

    # ═══════════ PASS 0: DNS PRE-FILTER ═══════════
    print(f"\n🔍 Pass 0: DNS Pre-filter (concurrency={MAX_CONCURRENT_DNS_PREFILTER})...")
    dns_sem = asyncio.Semaphore(MAX_CONCURRENT_DNS_PREFILTER)
    dns_start = time.time()

    async def dns_check(host):
        async with dns_sem:
            try:
                loop = asyncio.get_running_loop()
                ip = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, host),
                    timeout=3.0
                )
                return host, ip
            except Exception:
                return host, None

    dns_results = await asyncio.gather(*[dns_check(d) for d in domains])
    dns_map = {h: ip for h, ip in dns_results}
    live = [h for h, ip in dns_results if ip]
    dead = [h for h, ip in dns_results if not ip]
    dns_time = time.time() - dns_start
    print(f"   ✅ Done in {dns_time:.1f}s — {len(live)} live, {len(dead)} dead")

    # ═══════════ PASS 1: RDAP BATCH ═══════════
    print(f"\n⚡ Pass 1: RDAP Batch (concurrency={MAX_CONCURRENT_RDAP})...")
    rdap_sem = asyncio.Semaphore(MAX_CONCURRENT_RDAP)
    rdap_start = time.time()
    rdap_success = {}
    rdap_fail = []

    async def rdap_one(host, client):
        async with rdap_sem:
            t0 = time.time()
            try:
                url = f"{get_rdap_url(host)}{host}"
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    result = parse_rdap(data)
                    rdap_times.append(time.time() - t0)
                    return host, result
                elif resp.status_code == 429:
                    logger.warning(f"RDAP 429 rate limited: {host}")
                return host, None
            except Exception as e:
                logger.debug(f"RDAP failed for {host}: {e}")
                return host, None

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        raw = await asyncio.gather(*[rdap_one(h, client) for h in live], return_exceptions=True)

    for item in raw:
        if isinstance(item, Exception):
            continue
        h, data = item
        if data:
            rdap_success[h] = data
        else:
            rdap_fail.append(h)

    rdap_time = time.time() - rdap_start
    print(f"   ✅ Done in {rdap_time:.1f}s — {len(rdap_success)} success, {len(rdap_fail)} need WHOIS")

    # ═══════════ PASS 2: WHOIS FALLBACK ═══════════
    print(f"\n🐢 Pass 2: WHOIS Fallback (concurrency={MAX_CONCURRENT_WHOIS})...")
    whois_sem = asyncio.Semaphore(MAX_CONCURRENT_WHOIS)
    rate_limiter = RateLimiter(requests_per_minute=20)
    whois_start = time.time()
    whois_success = {}

    async def whois_one(host):
        async with whois_sem:
            await rate_limiter.acquire()
            t0 = time.time()
            for attempt in range(2):
                try:
                    loop = asyncio.get_running_loop()
                    w = await asyncio.wait_for(
                        loop.run_in_executor(None, whois.whois, host),
                        timeout=15
                    )
                    if w and w.domain_name:
                        result = {}
                        cd = w.creation_date
                        if isinstance(cd, list): cd = cd[0]
                        result["reg_date"] = str(cd) if cd else "NA"
                        result["registrar"] = w.registrar or "NA"
                        result["registrant_name"] = w.name or w.org or "NA"
                        result["registrant_country"] = w.country or "NA"
                        if w.name_servers:
                            result["name_servers"] = ";".join(str(ns) for ns in w.name_servers)
                        else:
                            result["name_servers"] = "NA"
                        whois_times.append(time.time() - t0)
                        return host, result
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    pass
                if attempt < 1:
                    await asyncio.sleep(1)
            return host, None

    raw = await asyncio.gather(*[whois_one(h) for h in rdap_fail], return_exceptions=True)
    for item in raw:
        if isinstance(item, Exception):
            continue
        h, data = item
        if data:
            whois_success[h] = data

    whois_time = time.time() - whois_start

    whois_failed = len(rdap_fail) - len(whois_success)
    print(f"   ✅ Done in {whois_time:.1f}s — {len(whois_success)} success, {whois_failed} failed")

    # ═══════════ SUMMARY ═══════════
    total_time = dns_time + rdap_time + whois_time
    total_success = len(rdap_success) + len(whois_success)
    total_failed = len(dead) + whois_failed

    # Estimate sequential time: avg 3s/domain for all domains
    estimated_sequential = len(domains) * 3.0

    print("\n" + "=" * 70)
    print("📊 SPEED BENCHMARK RESULTS")
    print("=" * 70)
    print(f"")
    print(f"  {'Pass':<25} {'Time':>8} {'Count':>8} {'Avg/domain':>12}")
    print(f"  {'─' * 25} {'─' * 8} {'─' * 8} {'─' * 12}")
    print(f"  {'DNS Pre-filter':<25} {dns_time:>7.1f}s {len(domains):>8} {dns_time/len(domains):>11.3f}s")
    rdap_avg = sum(rdap_times) / len(rdap_times) if rdap_times else 0
    print(f"  {'RDAP Batch':<25} {rdap_time:>7.1f}s {len(rdap_success):>8} {rdap_avg:>11.3f}s")
    whois_avg = sum(whois_times) / len(whois_times) if whois_times else 0
    print(f"  {'WHOIS Fallback':<25} {whois_time:>7.1f}s {len(whois_success):>8} {whois_avg:>11.3f}s")
    print(f"  {'─' * 25} {'─' * 8} {'─' * 8} {'─' * 12}")
    print(f"  {'TOTAL':<25} {total_time:>7.1f}s {total_success:>8}")
    print(f"")
    print(f"  📈 Domains: {len(domains)} total | {len(live)} live | {len(dead)} dead (DNS)")
    print(f"  ✅ Success: {total_success}/{len(domains)} ({100*total_success/len(domains):.0f}%)")
    print(f"  ❌ Failed:  {total_failed}/{len(domains)}")
    print(f"")
    print(f"  ⏱️  Parallel time:       {total_time:.1f}s")
    print(f"  🐌 Est. sequential time: {estimated_sequential:.0f}s")
    print(f"  🚀 Speedup:             {estimated_sequential/total_time:.1f}x faster")
    print("=" * 70)

    # ── Sample results ──
    print("\n📋 Sample RDAP results (first 5):")
    for i, (host, data) in enumerate(list(rdap_success.items())[:5]):
        print(f"   {i+1}. {host}: registrar={data.get('registrar','NA')}, date={data.get('reg_date','NA')}")

    if whois_success:
        print(f"\n📋 Sample WHOIS results (first 5):")
        for i, (host, data) in enumerate(list(whois_success.items())[:5]):
            print(f"   {i+1}. {host}: registrar={data.get('registrar','NA')}, date={data.get('reg_date','NA')}")


if __name__ == "__main__":
    asyncio.run(benchmark())

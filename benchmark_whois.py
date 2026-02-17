import asyncio
import time
import httpx
import logging
import dns.resolver
from tqdm.asyncio import tqdm
from phishing_pipeline.rdap_utils import lookup_rdap
import whois
from collections import Counter
import random

# Set up logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("benchmark")

# Configuration
MAX_CONCURRENT_RDAP = 10
MAX_CONCURRENT_WHOIS = 2  # Slightly increased from typical 1
WHOIS_TIMEOUT = 5.0      # Strict timeout to prevent blocking

# Semaphores
rdap_sem = asyncio.Semaphore(MAX_CONCURRENT_RDAP)
whois_sem = asyncio.Semaphore(MAX_CONCURRENT_WHOIS)

# Helper to generate test domains
def generate_test_domains(count=100):
    domains = [
        "google.com", "example.com", "microsoft.com", "github.com",
        "python.org", "wikipedia.org", "stackoverflow.com",
        "yandex.ru", "vk.com", "mail.ru",  # RU TLDs (often need WHOIS)
        "baidu.cn", "qq.com",              # CN TLDs
        "nonexistent-domain-123456.com",   # Dead (DNS fail)
        "timeout-test.xyz",                # Tricky
        "gov.in", "nic.in"                 # IN TLDs
    ]
    # Fill the rest with random domains to simulate load
    common_tlds = ["com", "net", "org", "io", "co", "ai"]
    for i in range(count - len(domains)):
        name = f"test-bench-{i}-{random.randint(1000,9999)}"
        tld = random.choice(common_tlds)
        domains.append(f"{name}.{tld}")
    return domains

async def check_dns(domain: str) -> bool:
    """Fast DNS check to skip dead domains."""
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, dns.resolver.resolve, domain, 'A')
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.resolver.NoNameservers):
        return False
    except Exception:
        return False

async def process_domain(domain: str, client: httpx.AsyncClient) -> str:
    """
    Pipeline: DNS -> RDAP -> WHOIS
    Returns status string.
    """
    # 1. DNS Check (Fastest)
    if not await check_dns(domain):
        return "DEAD (DNS)"

    # 2. RDAP Lookup (Fast, HTTP)
    async with rdap_sem:
        try:
            # Re-use the existing client
            rdap_res = await lookup_rdap(domain, client)
            if rdap_res.get("raw_rdap"):
                return "RDAP_MATCH"
            # If RDAP fails (404, 429), fall through
        except Exception as e:
            pass

    # 3. WHOIS Fallback (Slow, TCP port 43)
    async with whois_sem:
        try:
            loop = asyncio.get_running_loop()
            
            # wrapper for blocking 'whois' call
            def run_whois():
                return whois.whois(domain)

            # Strict 5s timeout
            w = await asyncio.wait_for(
                loop.run_in_executor(None, run_whois),
                timeout=WHOIS_TIMEOUT
            )
            
            # Check if we got valid data (whois library sometimes returns empty dict or partial data)
            if w and (w.creation_date or w.expiration_date or w.updated_date):
                 return "WHOIS_MATCH"
            else:
                 return "WHOIS_EMPTY"
                 
        except asyncio.TimeoutError:
            return "WHOIS_TIMEOUT"
        except Exception as e:
            return "WHOIS_FAIL"

async def main():
    domains = generate_test_domains(50)
    print(f"\n🚀 Starting Optimized Benchmark on {len(domains)} domains...")
    print(f"🔧 Config: RDAP={MAX_CONCURRENT_RDAP}, WHOIS={MAX_CONCURRENT_WHOIS}, Timeout={WHOIS_TIMEOUT}s")
    
    start_total = time.time()
    
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        tasks = [process_domain(d, client) for d in domains]
        
        results = []
        # tqdm.as_completed is not available in all versions, using manual tqdm
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Processing", unit="dom"):
            res = await f
            results.append(res)
            
    duration = time.time() - start_total
    
    print(f"\n✅ Completed in {duration:.2f}s (Avg: {duration/len(domains):.2f}s/domain)")
    
    # Stats
    stats = Counter(results)
    print("\n📊 Results Breakdown:")
    for status, count in stats.most_common():
        print(f"  {status:<15}: {count}")

if __name__ == "__main__":
    # Fix for Windows loop policy if needed
    import sys
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    asyncio.run(main())

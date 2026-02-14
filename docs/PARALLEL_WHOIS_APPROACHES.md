# Parallel WHOIS/RDAP Retrieval Approaches

> **Date**: 12-02-2026  
> **Scope**: WHOIS Phase 2 of `pipeline.py` only  
> **Current Implementation**: Sequential RDAP-first → WHOIS-fallback, rate-limited at 20 RPM

---

## 1. Dual VPN on the Same Device/IP — What Happens?

### How VPNs Work (Network-Level)

A VPN creates an **encrypted tunnel** that routes all (or some) of your traffic through a remote server. Your real IP is masked by the VPN server's IP.

### What Happens with 2 VPNs Simultaneously?

| Scenario | Behavior | Result |
|----------|----------|--------|
| **VPN-over-VPN (chaining)** | VPN1 encrypts traffic → VPN2 encrypts again → Internet | Double encryption, **significantly slower** (~2-5x latency increase). Only the exit IP of VPN2 is visible to WHOIS servers |
| **Split-tunnel (2 separate adapters)** | VPN1 handles some traffic, VPN2 handles other traffic via routing rules | Possible but complex. OS routing table conflicts are common |
| **Same default route conflict** | Both VPNs fight for the default gateway (0.0.0.0/0) | ❌ **One VPN wins**, the other silently drops. Unreliable behavior |

### Practical Reality

> [!CAUTION]
> Running 2 VPNs on the **same device** typically causes:
>
> - **Routing table conflicts** — Only one default route can exist
> - **DNS leaks** — DNS queries may bypass one or both tunnels
> - **Connection drops** — VPN keepalives interfere with each other
> - **No parallelism** — Traffic still goes through a single network stack sequentially

**Bottom line**: Two VPNs on one machine do **NOT** give you two independent outbound IPs for parallel requests. They fight over the same network stack.

---

## 2. Is Dual-VPN Useful for Our WHOIS/RDAP Pipeline?

### Short Answer: **No meaningful benefit**

| Factor | Why It Doesn't Help |
|--------|---------------------|
| **Rate limiting** | WHOIS servers rate-limit by **source IP**. With VPN chaining, you still have 1 exit IP |
| **Parallelism** | Our bottleneck is WHOIS server response time (~3-5s), not our outbound bandwidth |
| **RDAP is already fast** | RDAP lookups average ~0.3-0.5s (HTTP/JSON). No VPN needed to speed this up |
| **Complexity** | VPN management adds failure modes without throughput gain |

> [!IMPORTANT]
> The real bottleneck in Phase 2 is the **sequential processing loop** (line 580 of `pipeline.py`) — we process domains one-at-a-time, waiting for each WHOIS response before starting the next.

---

## 3. Current Pipeline Architecture (Phase 2)

```
┌──────────────────────────────────────────────────┐
│              For each domain (sequential)         │
│                                                    │
│   ┌──────────────┐     ┌──────────────────────┐   │
│   │  Try RDAP    │────▶│ Success? Use result   │   │
│   │  (httpx,8s)  │     └──────────────────────┘   │
│   └──────┬───────┘                                 │
│          │ Failed                                   │
│   ┌──────▼───────┐     ┌──────────────────────┐   │
│   │  Rate Limit  │────▶│  Try WHOIS (15s max)  │   │
│   │  (20 RPM)    │     │  2 retries            │   │
│   └──────────────┘     └──────────────────────┘   │
│                                                    │
│   Wait for result → next domain                    │
└──────────────────────────────────────────────────┘
```

**Problem**: 500 domains × ~3s avg = **25 minutes** just for WHOIS Phase 2.

---

## 4. Official Rate Limits — RDAP & WHOIS (From Documentation)

### 4.1 RDAP Bootstrap Server (`rdap.org`)

| Parameter | Value | Source |
|-----------|-------|--------|
| **Max requests** | 10 in 10 seconds (1 req/sec average) | [rdap.org](https://rdap.org) — Cloudflare enforced |
| **Penalty** | HTTP 429 + temporary block | rdap.org docs |
| **Bypass** | ✅ Use authoritative RDAP servers directly instead of the bootstrap redirect | RFC 9224 recommendation |

> [!IMPORTANT]
> `rdap.org` is just a **redirect service** (HTTP 302). It doesn't host data itself — it redirects you to the authoritative RDAP server. The 10/10s limit applies only to rdap.org, **NOT** to the actual registry RDAP servers. By going directly to the authoritative server, we bypass this bottleneck entirely.

### 4.2 Authoritative RDAP Servers (Per Registry)

| Registry | TLDs | RDAP Rate Limit | WHOIS (Legacy) Rate Limit | Source |
|----------|------|-----------------|---------------------------|--------|
| **Verisign** | `.com`, `.net` | No published limit (ToS: no "high-volume automated processes") | ~1 req/sec (~86,400/day) | [verisign.com ToS](https://www.verisign.com/en_US/channel-resources/domain-registry-products/whois/index.xhtml) |
| **PIR** | `.org` | No published RDAP limit | 10 queries/min/IP | PIR WHOIS policy |
| **NIXI** | `.in` | No published limit (ToS-based) | Not publicly documented | [nixiregistry.in](https://nixiregistry.in) |
| **CentralNic** | `.xyz`, `.online`, `.site`, etc. | Not published | 1,800 queries/15min per /24 subnet | CentralNic WHOIS policy |
| **Nominet** | `.uk` | Not published | 5 q/s, 1,000/day per user | Nominet WHOIS AUP |
| **GoDaddy Registry** | Various new gTLDs | Not published | 20/hour, 200/day | GoDaddy Registry WHOIS |

> [!NOTE]
> **Key insight**: Most authoritative RDAP servers do **not** publish explicit numerical rate limits. They use Terms of Service language ("no automated high-volume queries") and enforce dynamically via HTTP 429. This means:
>
> - We can safely run **5-10 concurrent RDAP requests** without hitting limits
> - If we get a 429, we implement exponential backoff + `Retry-After` header (per RFC 7480)
> - WHOIS (port 43) is the one with strict, low limits (~1 req/sec for most registries)

### 4.3 WHOIS Port 43 (Legacy) — Key Limits

| Registrar/Registry | Rate Limit | Notes |
|--------------------|------------|-------|
| **OpenSRS/Tucows** | 1 lookup/sec/IP, 1 connection at a time | Rejects simultaneous connections |
| **CentralNic** | 1,800 queries/15min per /24 block | Counts all IPs in your subnet together |
| **Nominet (.uk)** | 5 q/s, 1,000/day/user | WHOIS2 gateway: 100 q/s, 100k/day |
| **Polish registry** | 100 queries/day/IP | One of the strictest |
| **GoDaddy** | 20/hour, 200/day | Very restrictive |

> [!WARNING]
> **ICANN sunsetted WHOIS Port 43 on January 28, 2025** in favor of RDAP. This means WHOIS is becoming increasingly unreliable and may stop working for some TLDs. Prioritizing RDAP is the correct long-term strategy.

### 4.4 Recommended Safe Concurrency for Our Pipeline

Based on official documentation:

| Protocol | Safe Concurrency | Maximum (risky) | Justification |
|----------|-------------------|------------------|---------------|
| **RDAP via `rdap.org`** | 1 req/sec (10/10s) | Don't push it | Cloudflare will block you |
| **RDAP direct to Verisign** | **5-10 concurrent** | 15-20 concurrent | No published limit; honor 429 + backoff |
| **RDAP direct to PIR/NIXI** | **3-5 concurrent** | 10 concurrent | More conservative; less infrastructure |
| **WHOIS fallback** | **1 req/3sec** (current 20 RPM) | 1 req/sec | Strict per-IP limits; our current setting is safe |

> [!TIP]
> **Optimal strategy**: Skip `rdap.org` bootstrap entirely. Map TLD → authoritative RDAP URL directly, then use 5-10 concurrent connections per registry. This gives us **5-10x throughput** with zero risk of hitting rdap.org's bottleneck.

---

## 5. Parallel WHOIS Retrieval Approaches

### Approach 1: `asyncio.Semaphore` Batched Concurrency ⭐ (Recommended)

**Concept**: Run N WHOIS lookups concurrently using asyncio, controlled by a semaphore.

```python
# Conceptual implementation
async def parallel_whois_phase(domains, max_concurrent=5):
    semaphore = asyncio.Semaphore(max_concurrent)
    rdap_client = httpx.AsyncClient(follow_redirects=True, timeout=10.0)
    
    async def lookup_one(domain):
        async with semaphore:
            # Try RDAP first (already async)
            result = await rdap_lookup(domain, timeout=8.0)
            if result:
                return domain, result, "RDAP"
            
            # Fallback to WHOIS (run in executor)
            await rate_limiter.acquire()
            loop = asyncio.get_running_loop()
            w = await asyncio.wait_for(
                loop.run_in_executor(None, whois.whois, domain),
                timeout=15
            )
            return domain, parse_whois(w), "WHOIS"
    
    # Launch ALL lookups, semaphore controls concurrency
    tasks = [lookup_one(d) for d in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    await rdap_client.aclose()
    return results
```

| Metric | Current | With Semaphore(5) | With Semaphore(10) |
|--------|---------|--------------------|--------------------|
| **Time for 500 domains** | ~25 min | ~5 min | ~2.5 min |
| **Risk of rate-limit ban** | Low | Low | Medium |
| **Implementation effort** | — | Low | Low |

> [!TIP]
> Start with `max_concurrent=5` for WHOIS and unlimited for RDAP (RDAP servers are more tolerant). RDAP calls are already async and lightweight.

---

### Approach 2: Separate RDAP and WHOIS Passes (Two-Pass Strategy)

**Concept**: Run ALL RDAP lookups first (fast, no rate limit), then only WHOIS for failures.

```
Pass 1: RDAP (all domains, high concurrency)
    ┌───────────┐  ┌───────────┐  ┌───────────┐
    │ domain 1  │  │ domain 2  │  │ domain N  │
    │  RDAP     │  │  RDAP     │  │  RDAP     │  ← 20-50 concurrent
    └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
          ▼              ▼              ▼
    [success list]     [fail list]
    
Pass 2: WHOIS (failures only, limited concurrency)
    ┌───────────┐  ┌───────────┐
    │ failed 1  │  │ failed 2  │
    │  WHOIS    │  │  WHOIS    │  ← 3-5 concurrent
    └───────────┘  └───────────┘
```

**Why this is effective**:

- RDAP succeeds for **~70-80% of .com/.net/.org** domains
- RDAP has no rate limiting (HTTP REST API)
- Only 20-30% of domains need the slow WHOIS fallback
- WHOIS pass can be rate-limited independently

| Metric | Estimated Improvement |
|--------|----------------------|
| Pass 1 (RDAP, 50 concurrent) | ~10-15 seconds for 500 domains |
| Pass 2 (WHOIS, 5 concurrent) | ~3-5 min for ~100-150 failures |
| **Total** | **~3-5 min vs current ~25 min** |

---

### Approach 3: Multi-Source RDAP Endpoints

**Concept**: Instead of using only `rdap.org`, query multiple RDAP bootstrap servers in parallel and take the first response.

```python
RDAP_ENDPOINTS = [
    "https://rdap.org/domain/",
    "https://rdap.verisign.com/com/v1/domain/",     # .com/.net
    "https://rdap.markmonitor.com/rdap/domain/",
    "https://rdap.nic.in/domain/",                   # .in domains  
]

async def multi_rdap(domain, client):
    """Race multiple RDAP endpoints, return first success."""
    tasks = []
    for endpoint in RDAP_ENDPOINTS:
        tasks.append(client.get(f"{endpoint}{domain}"))
    
    # Return first successful response
    for coro in asyncio.as_completed(tasks):
        try:
            resp = await asyncio.wait_for(coro, timeout=5.0)
            if resp.status_code == 200:
                return resp.json()
        except:
            continue
    return None
```

| Benefit | Risk |
|---------|------|
| Faster results (first-responder wins) | Not all endpoints support all TLDs |
| Built-in redundancy | Some may block rapid queries |
| No WHOIS fallback needed for most domains | Need to maintain endpoint list |

> [!NOTE]
> This approach works best combined with **TLD-aware routing** — send `.com` domains directly to Verisign's RDAP, `.in` to NIXI's RDAP, etc., rather than going through the bootstrap redirect.

---

### Approach 4: DNS-Based Pre-filtering (Skip Dead Domains)

**Concept**: Before WHOIS lookup, do a fast DNS resolution. If the domain doesn't resolve, skip the expensive WHOIS call.

```python
async def dns_prefilter(domains):
    """Quick DNS check: skip domains that don't resolve."""
    live_domains = []
    dead_domains = []
    
    async def check_dns(domain):
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, domain),
                timeout=2.0
            )
            return domain, True
        except:
            return domain, False
    
    results = await asyncio.gather(*[check_dns(d) for d in domains])
    for domain, alive in results:
        (live_domains if alive else dead_domains).append(domain)
    
    return live_domains, dead_domains
```

**Impact**: Typically 10-20% of domains in phishing datasets are dead/parked → saves that many WHOIS lookups entirely.

---

### Approach 5: Local WHOIS Cache (SQLite)

**Concept**: Cache successful WHOIS/RDAP results locally. If a domain was looked up recently, reuse the cached result.

```python
import sqlite3, json, time

class WhoisCache:
    def __init__(self, db_path="whois_cache.db", ttl_hours=24):
        self.conn = sqlite3.connect(db_path)
        self.ttl = ttl_hours * 3600
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                domain TEXT PRIMARY KEY,
                data TEXT,
                method TEXT,
                timestamp REAL
            )
        """)
    
    def get(self, domain):
        row = self.conn.execute(
            "SELECT data, method FROM cache WHERE domain=? AND timestamp>?",
            (domain, time.time() - self.ttl)
        ).fetchone()
        if row:
            return json.loads(row[0]), row[1]
        return None, None
    
    def put(self, domain, data, method):
        self.conn.execute(
            "INSERT OR REPLACE INTO cache VALUES (?,?,?,?)",
            (domain, json.dumps(data, default=str), method, time.time())
        )
        self.conn.commit()
```

**When this helps**:

- Re-running the pipeline on overlapping domain sets
- Testing/debugging Phase 2 repeatedly
- Domains that appear in multiple CSE holdout batches

---

### Approach 6: Producer-Consumer with Priority Queue

**Concept**: Use an async queue where RDAP results feed back into the pipeline immediately, while WHOIS failures queue up for slower processing.

```
Producer (spawns lookups)
    │
    ├──▶ RDAP Worker Pool (fast, 20 workers)
    │        │
    │        ├── Success → Results Queue → Consumer (writes CSV)
    │        └── Failure → WHOIS Queue ──┐
    │                                     │
    └──▶ WHOIS Worker Pool (slow, 3 workers) ◀──┘
             │
             └── Results Queue → Consumer (writes CSV)
```

```python
async def producer_consumer_whois(domains):
    rdap_queue = asyncio.Queue()
    whois_queue = asyncio.Queue()
    results = {}
    
    # Fill RDAP queue
    for d in domains:
        await rdap_queue.put(d)
    
    async def rdap_worker():
        while not rdap_queue.empty():
            domain = await rdap_queue.get()
            result = await rdap_lookup(domain)
            if result:
                results[domain] = (result, "RDAP")
            else:
                await whois_queue.put(domain)  # Escalate to WHOIS
            rdap_queue.task_done()
    
    async def whois_worker():
        while True:
            domain = await whois_queue.get()
            await rate_limiter.acquire()
            result = await whois_fallback(domain)
            results[domain] = (result, "WHOIS")
            whois_queue.task_done()
    
    # Start workers
    rdap_workers = [asyncio.create_task(rdap_worker()) for _ in range(20)]
    whois_workers = [asyncio.create_task(whois_worker()) for _ in range(3)]
    
    await rdap_queue.join()
    await whois_queue.join()
    
    # Cancel idle WHOIS workers
    for w in whois_workers:
        w.cancel()
    
    return results
```

---

## 6. Comparison Matrix

| Approach | Speed Gain | Implementation Effort | Risk Level | Best For |
|----------|-----------|----------------------|------------|----------|
| **1. Semaphore Batching** ⭐ | 5-10x | 🟢 Low | 🟢 Low | Quick win, minimal code change |
| **2. Two-Pass (RDAP→WHOIS)** | 5-8x | 🟢 Low | 🟢 Low | Cleanest separation of concerns |
| **3. Multi-Source RDAP** | 1.5-2x | 🟡 Medium | 🟡 Medium | Resilience + speed for RDAP |
| **4. DNS Pre-filter** | 1.1-1.2x | 🟢 Low | 🟢 Low | Eliminating dead domain waste |
| **5. Local Cache** | ∞ (cache hit) | 🟢 Low | 🟢 Low | Repeated pipeline runs |
| **6. Producer-Consumer** | 5-10x | 🔴 High | 🟡 Medium | Maximum throughput, complex |

---

## 7. Recommended Strategy (Combine 1 + 2 + 4 + 5)

The highest ROI approach combines multiple simple techniques:

```
Step 1: DNS Pre-filter (Approach 4)
    → Remove dead domains from the lookup list
    
Step 2: Check Local Cache (Approach 5)
    → Skip domains already looked up recently
    
Step 3: RDAP Batch (Approach 2, Pass 1)
    → Hit all remaining domains with RDAP concurrently (semaphore=20)
    
Step 4: WHOIS Fallback Batch (Approach 2, Pass 2)  
    → Only failed domains, concurrent with semaphore=3-5
```

**Expected result**: Phase 2 drops from **~25 minutes → ~2-4 minutes** for 500 domains.

> [!IMPORTANT]
> None of these approaches require VPNs, proxy rotation, or any network infrastructure changes. They all work with our existing single IP and internet connection.

---

## 8. What Would Actually Need Multiple IPs?

For completeness, scenarios where multiple IPs (not dual-VPN) would help:

| Method | How | Use Case |
|--------|-----|----------|
| **Proxy rotation** (e.g., `rotating-proxy` services) | Each WHOIS request exits via a different IP | Avoiding per-IP rate limits when doing 10,000+ lookups |
| **Multi-machine cluster** | Distribute domains across machines with different IPs | Large-scale bulk WHOIS |
| **Cloud functions** (Lambda, Cloud Run) | Each invocation gets a fresh IP | Serverless parallel WHOIS at scale |

> [!WARNING]
> These are usually needed only at **10,000+ domain scale**. For our pipeline's typical batch sizes (100-500 domains), the approaches in Section 4 are more than sufficient.

import sys

def main():
    try:
        with open('comparison.py', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        new_lines = []
        for line in lines:
            if line.startswith('import json'):
                new_lines.append('import json\nimport ray\n')
            elif line.startswith('async def run_hashing_shortlist_async'):
                break
            else:
                new_lines.append(line)
        
        new_content = ''.join(new_lines)
        
        ray_append = """###############################################
# RAY DISTRIBUTED DETECTION
###############################################

@ray.remote(num_gpus=1)
class GPUInferenceActor:
    def __init__(self, clip_matrix_np):
        import torch
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.gpu_clip_matrix = torch.tensor(clip_matrix_np, dtype=torch.float32, device=self.device)

    def score_batch(self, images, cpu_scores_batch):
        import torch
        import numpy as np
        if not images:
            return []
        
        clip_embeddings = get_clip_embeddings_batch(images, batch_size=len(images))
        sv = torch.tensor(clip_embeddings, dtype=torch.float32, device=self.device)
        sv = sv / sv.norm(dim=1, keepdim=True).clamp(min=1e-8)
        
        all_sims = torch.mm(self.gpu_clip_matrix, sv.T).cpu().numpy()
        
        n_entities = len(_entity_index["names"])
        results = []
        for b in range(len(images)):
            scores = cpu_scores_batch[b].copy()
            
            # all_sims is shape (M, B)
            if all_sims.ndim > 1:
                all_sims_b = all_sims[:, b]
            else:
                all_sims_b = all_sims
            
            for i in range(n_entities):
                mask = _entity_index["clip_entity_idx"] == i
                if mask.any():
                    scores[i] += float(all_sims_b[mask].max()) * WEIGHTS["screenshot"]
            
            scores = (scores / _TOTAL_WEIGHT) * 100
            best_idx = int(np.argmax(scores))
            results.append({
                "entity": _entity_index["names"][best_idx], 
                "score": float(scores[best_idx])
            })
        return results

@ray.remote(num_cpus=1)
def process_url_chunk_ray(chunk_urls, gpu_actor_handle):
    import asyncio
    return asyncio.run(_async_process_chunk(chunk_urls, gpu_actor_handle))

async def _async_process_chunk(chunk_urls, gpu_actor_handle):
    import asyncio
    import aiohttp
    from playwright.async_api import async_playwright
    from PIL import Image
    from io import BytesIO
    import numpy as np

    semaphore = asyncio.Semaphore(16)
    connector = aiohttp.TCPConnector(limit=32) if _has_aiohttp else None
    aio_session = aiohttp.ClientSession(connector=connector) if _has_aiohttp else None
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        tasks = [fetch_features(u, browser, semaphore, aio_session) for u in chunk_urls]
        chunk_features = await asyncio.gather(*tasks)
        await browser.close()
    if aio_session:
        await aio_session.close()

    images = []
    cpu_scores_list = []
    final_urls = []
    
    n_entities = len(_entity_index["names"])
    
    for url, domain, screenshot, words, fav_hash in chunk_features:
        if screenshot is None:
            continue
        images.append(Image.open(BytesIO(screenshot)))
        final_urls.append(url)
        
        scores = np.zeros(n_entities, dtype="float64")
        for i in range(n_entities):
            scores[i] += domain_similarity(domain, _entity_index["domains"][i]) * WEIGHTS["domain"]
            if fav_hash and fav_hash in _entity_index["fav_sets"][i]:
                scores[i] += WEIGHTS["favicon"]
            if _entity_index["kw_sets"][i]:
                overlap = len(words & _entity_index["kw_sets"][i])
                scores[i] += min(overlap / 5, 1.0) * WEIGHTS["keywords"]
        cpu_scores_list.append(scores)
        
    if not images:
        return []
        
    cpu_scores_batch = np.array(cpu_scores_list, dtype="float32")
    # RPC to the hot VRAM Actor!
    gpu_results = await gpu_actor_handle.score_batch.remote(images, cpu_scores_batch)
    
    out = []
    for url, res in zip(final_urls, gpu_results):
        out.append((url, res["entity"], res["score"]))
    return out

def run_hashing_shortlist_ray(url_list, threshold=65):
    import pandas as pd
    import time
    t0 = time.perf_counter()
    
    # Pre-init Ray using EPYC's 48 CPUs and H100 GPU
    if not ray.is_initialized():
        ray.init(ignore_reinit_error=True)
        
    chunk_size = 128
    print(f"🚀 Submitting {len(url_list)} URLs to Ray Cluster across CPUs and 1 GPU...")
    
    gpu_actor = GPUInferenceActor.remote(_entity_index["clip_matrix"])
    
    futures = []
    # Send chunks rapidly as asynchronous Ray RPC Tasks
    for i in range(0, len(url_list), chunk_size):
        chunk = url_list[i : i+chunk_size]
        futures.append(process_url_chunk_ray.remote(chunk, gpu_actor))
        
    results = []
    while futures:
        ready, futures = ray.wait(futures, num_returns=1, timeout=0.1)
        for f in ready:
            res_list = ray.get(f)
            for url, best_entity, best_score in res_list:
                if best_score > threshold:
                    print(f"✅ {url} -> {best_entity} ({best_score:.1f}%)")
                    results.append((url, best_entity, best_score))
                else:
                    print(f"❌ {url} -> None (best: {best_entity} {best_score:.1f}%)")
                
    elapsed = time.perf_counter() - t0
    print(f"\\n⏱ Ray Processing done in {elapsed:.1f}s ({len(url_list)} URLs)")
    
    # Optional cleanup for long running instances
    ray.shutdown()
    
    rows = []
    for target_url, best_entity, best_score in results:
        rows.append({
            "Cooresponding CSE": best_entity,
            "Identified Phishing/Suspected Domain Name": target_url
        })
    return pd.DataFrame(rows)

def run_hashing_shortlist(url_list, threshold=65):
    return run_hashing_shortlist_ray(url_list, threshold)

if __name__ == "__main__":
    test_urls = [
        "https://www.onlinesbi.sbi/",
        "http://airtel.in",
        "http://myjio.login.com",
    ]
    df = run_hashing_shortlist_ray(test_urls)
    print(df)
"""
        with open('comparison.py', 'w', encoding='utf-8') as f:
            f.write(new_content)
            f.write(ray_append)
        print("Successfully rewrote comparison.py with Ray architecture.")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()

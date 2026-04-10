# Pipeline Analysis and Bottlenecks

- **Review current design:** Gather the existing pipeline diagram and metric logs (throughput, CPU/GPU utilization, queue depths). For example, an Oracle video-processing pipeline case showed only ~12% GPU utilization because upstream CPU stages (data decoding) were starved【7†L59-L64】.  Similarly, plot queue depths for each stage: if an upstream queue grows while a downstream queue stays empty, it indicates a bottleneck at the upstream stage【7†L130-L138】.
- **Stage breakdown:** Identify each pipeline stage (e.g. web crawling, parsing, feature extraction, ML inference, result writing). Note which are I/O-bound (network requests, disk I/O) vs CPU-bound (text/image processing) vs GPU-bound (model inference). Measure each stage’s throughput (items/sec) and resource use. The end-to-end throughput cannot exceed the slowest (bottleneck) stage【7†L92-L100】.
- **Instrumentation:** Use monitoring tools (e.g. Prometheus/Grafana or CloudWatch) to record CPU load, GPU utilization, memory usage, and queue lengths per stage. Look for signals of underutilization: e.g. consistently low GPU load (<20%) while CPU usage is high or queues fill up【7†L59-L64】【22†L49-L57】. This confirms the GPUs are waiting for data.
- **Summarize findings:** Document which stage(s) are under-provisioned. For instance, if crawling/parsing stages run single-threaded, they might be far slower than the GPU inference stage, causing idle GPUs. List the observed resource ceilings (e.g., CPU cores idle, GPU idle, RAM usage).

## Concurrency and Parallelism Strategies

- **I/O-bound tasks – Asynchronous and multithreading:** For heavy web-scraping or network I/O, use asynchronous libraries (e.g. Python’s `asyncio` with `aiohttp`, or Node.js). Instead of sequential requests (which block on network), fire many requests concurrently. For example, a simple asyncio scraper:  

    ```python
    import asyncio, aiohttp
    
    async def fetch_url(session, url):
        async with session.get(url) as resp:
            return await resp.text()
    
    async def main(urls):
        async with aiohttp.ClientSession() as session:
            # Start one fetch task per URL
            tasks = [fetch_url(session, url) for url in urls]
            html_pages = await asyncio.gather(*tasks)  # Run all concurrently
            for html in html_pages:
                process(html)  # e.g. parse or push to next stage
    
    asyncio.run(main(list_of_urls))
    ```
    - **What it does:** `aiohttp` lets each request run without blocking the others. All requests are sent “at once” and responses are handled as they arrive. This maximizes I/O throughput【20†L81-L90】【20†L99-L107】. In a real pipeline, use such async loops to crawl many URLs in parallel.
    - **Benefit:** Dramatically faster fetch rates. As one author notes, asynchronous scraping can handle 10–50 requests in parallel, giving nearly 10–50× speedup versus sequential waits【20†L81-L90】【20†L99-L107】.
- **CPU-bound tasks – Multithreading vs Multiprocessing:** If stages are CPU-intensive (e.g. HTML parsing, image decoding, feature extraction), Python’s GIL means threads won’t fully utilize multicore CPUs. Use multiprocessing or native libraries:
    - *Multiprocessing:*  
      ```python
      from concurrent.futures import ProcessPoolExecutor
      
      def parse_item(item):
          # CPU-heavy processing of an item
          ...
      
      with ProcessPoolExecutor(max_workers=8) as executor:
          results = list(executor.map(parse_item, item_list))
      ```
      This creates separate Python processes to use all CPU cores. Each process handles a chunk of data in parallel.
    - *Vectorized/batched libraries:* Use libraries that internally parallelize (e.g. pandas, NumPy, OpenCV often use C-level multi-threading). 
    - *Pitfalls:* Spawning too many processes can lead to context-switch overhead. Tune `max_workers` to roughly the number of physical cores.
- **Distributed task frameworks:** For very large scale, use distributed systems like **Ray** or **Celery**:
    - *Example with Ray:* Wrapping functions as Ray tasks enables cluster-wide parallelism. For instance, a web crawler was speeded up ~4× by turning crawling into parallel Ray tasks【24†L974-L980】:
      ```python
      import ray
      ray.init()  # Start Ray
    
      @ray.remote
      def fetch_links(start_url):
          return find_links(start_url)  # user-defined link extraction
    
      urls = ["https://site1.com", "https://site2.com", ...]
      # Launch one task per URL
      futures = [fetch_links.remote(u) for u in urls]
      all_links = ray.get(futures)  # Runs tasks in parallel
      ```
      This pattern (async tasks and `ray.get`) lets Ray schedule work on all available CPUs. In the cited example, six crawlers ran ~4× pages in the same time as one sequential crawler【24†L974-L980】.
    - *Queues & Workers:* Message queues (Kafka, RabbitMQ, AWS SQS) with worker pools also achieve concurrency. Each worker pulls tasks asynchronously.
- **Concurrency vs Parallelism:** Recall that *concurrency* (overlapping tasks) can improve utilization on one core, while *parallelism* (multiple cores/GPUs) speeds up heavy work by truly simultaneous execution【19†L51-L59】【19†L124-L129】. In practice, combine both: e.g. use `asyncio` for I/O concurrency and multiple processes or machines for CPU/GPU parallelism.

## CPU, GPU and Memory Allocation Strategies

- **Match tasks to resources:** Partition the pipeline into CPU-heavy and GPU-heavy stages. For GPU inference, ensure data arrives in batches to keep GPUs fed. If GPUs sit idle (~10–20% utilization), the system is *waiting* for data【7†L59-L64】【22†L49-L57】.
- **GPU utilization:** GPUs are expensive; underutilization wastes cost【22†L49-L57】. Monitor **GPU utilization (%)** (compute cores active) and **GPU memory use**. For example, if you see <20% compute usage but queues are empty, focus on feeding the GPU stage faster【7†L59-L64】【22†L49-L57】.  
- **GPU resource sharing:** Use technologies like NVIDIA **MIG** (Multi-Instance GPU) to partition a single GPU into smaller units. AWS SageMaker HyperPod with MIG allows multiple tasks to share one GPU, increasing utilization【26†L53-L61】. In practice, you might run several smaller models or parallel inference tasks on one GPU. As AWS notes, MIG lets “multiple users and tasks access GPU resources simultaneously” and improves overall GPU efficiency【26†L53-L61】【26†L121-L128】.
- **CPU allocation:** For CPU-bound stages, ensure enough CPU cores are allocated. In a container/Kubernetes context, set proper CPU *requests* and *limits* so the scheduler can place pods optimally. For example, an **NVIDIA H100** machine without NVENC encoding left most CPU cores idle until transcoding was parallelized【7†L173-L181】. Tuning libraries (e.g. telling FFmpeg to use all threads) can dramatically raise throughput.
- **Memory:** Stream data between stages instead of loading it all in memory. Use bounded queues or chunking to keep memory stable. For large objects (images, HTML), free or reuse buffers promptly. If using GPUs, ensure RAM is sufficient to hold batches or intermediate results (e.g. batch size selection to fit VRAM).
- **Autoscaling:** Use autoscalers tuned to metrics. For CPU stages, scale by CPU usage or queue length. For GPU stages, scale by GPU utilization or task backlog. On Kubernetes, you might run separate node pools (or instance groups) for GPU instances (e.g., AWS `p4d` instances) and CPU instances. Set autoscaling policies so that if GPU pods idle (low GPU util) but CPU queue grows, add more CPU workers, and vice versa.
- **Isolation and quotas:** In Kubernetes, request GPU resources via `nvidia.com/gpu`. Also consider Kubernetes [Dynamic Resource Allocation](https://kubernetes.io/docs/concepts/scheduling-eviction/extend-resources/) if available, so pods can share GPUs when idle【22†L49-L57】. At the OS level, Linux Cgroups or MPS (NVIDIA Multi-Process Service) can allow sharing GPUs among processes.

【18†embed_image】 *Figure: Example data pipeline architecture with parallel processing stages. Each stage (ingestion, parsing, analysis, inference, storage) runs on its own pool of workers. Stages communicate via queues, allowing each to scale independently and preventing upstream bottlenecks from starving downstream GPUs.* 

## Redesigned Pipeline Architecture

1. **Decoupled stage graph:** Architect the phishing pipeline as a graph of connected stages, each with its own worker pool and queue【7†L80-L89】【10†L468-L474】. For example: 
   - *Stage 1:* URL ingestion (async fetch or crawl)  
   - *Stage 2:* Content parsing/feature extraction (CPU threads)  
   - *Stage 3:* ML inference (GPU pods)  
   - *Stage 4:* Results aggregation/storage  
   Each arrow between stages is a queue (e.g., Kafka topic or SQS queue). This follows the “bounded queues with backpressure” pattern【7†L80-L89】: if one stage lags, its input queue grows but doesn’t overflow others.
2. **Concurrency per stage:** Tune each stage’s concurrency separately. For example, run 20 async crawler instances, 10 CPU parsers, and 4 GPU inference pods. **Separate queues** enable independent scaling – the ML classifier can spin up more GPU pods if its queue lengthens, without touching the crawlers【10†L468-L474】.
3. **Data flow with feedback:** Implement backpressure. If a stage cannot keep up, either drop or throttle new tasks upstream to avoid memory explosion. For instance, if the parsing stage queue is full, pause ingestion or slow down crawling.
4. **GPU tier as sink:** Make the GPU (inference) stage the final compute tier. Upstream stages should batch and normalize data into *“inference-ready”* chunks. For example, batch multiple URLs' features before sending to the model, to exploit GPU parallelism (large batches amortize overhead, as seen in dual GPU/CPU pipelines【10†L428-L436】). 
5. **Pipeline orchestration:** Use a workflow/orchestration tool: e.g. Apache Airflow, AWS Step Functions, or Kubernetes (with operators). Each task can be a containerized microservice (using Docker/Kubernetes or serverless functions). For example, one might use Kubernetes Jobs or Argo Workflows to pull a batch from the queue, process it, and push results.
6. **Monitoring and alerts:** Insert observability at each stage: record items/sec, queue depth, error rates. Use dashboards or alerts (like “queue depth high”) to auto-scale or debug. As one pipeline lesson noted, “queue depth tells you something is about to break”【10†L475-L482】. Set alerts on queue build-up and low GPU utilization.
7. **Parallelism in practice:** An orchestration example could be Ray or Dask: submit tasks to a Ray cluster, where each remote function processes an item and returns results. The Ray autoscaler can add nodes (CPU or GPU) dynamically. Alternatively, use Kubernetes with Horizontal Pod Autoscalers based on custom metrics (like GPU util).
8. **AWS-specific tips:** If on AWS, consider separate ECS/EKS clusters or node groups: use `fargate` for light tasks, `EC2 Spot` GPU nodes for inference. Terraform can define node groups for CPU vs GPU with scaling policies. AWS Batch is another option: define CPU and GPU compute environments and job queues.

## Implementation Steps and Validation

- **Step 1: Instrument and profile.** Deploy monitoring and run the pipeline under load. Confirm which stages are slow.  
- **Step 2: Incremental parallelization.** Start by parallelizing the most obvious bottleneck: e.g. switch crawling to `asyncio` or spawn multiple scraper processes. Measure speedup (ideally linear until bottleneck shifts)【24†L974-L980】.  
- **Step 3: Micro-benchmark stages.** Write small tests for each stage (e.g. parse 100 pages) to tune thread/process counts.  
- **Step 4: Deploy a queue between stages.** If not present, insert a messaging layer (Kafka/SQS). Ensure producers and consumers can run independently.  
- **Step 5: Containerize pipeline services.** Build Docker images for each stage. Use Terraform/Helm to deploy to Kubernetes. Specify CPU/GPU resources in Pod specs (e.g. `requests: cpu=500m, nvidia.com/gpu=1`).  
- **Step 6: Configure autoscaling.** Set up HPA (Horizontal Pod Autoscaler) on CPU-heavy deployments (scale on CPU util or custom app metric) and custom autoscaling for GPU pods (scale by queue length or GPU util via metrics server).  
- **Step 7: Enable GPU sharing (if needed).** If using NVIDIA GPUs, install device plugins or MIG drivers. On AWS, enable MIG on suitable instance types to run multiple inference processes per GPU【26†L53-L61】.  
- **Step 8: Test end-to-end.** Run synthetic workloads and measure total throughput (items/sec) and latency. Compare to baseline. Aim to saturate both CPU and GPU (e.g. 70–80% utilization on each) without building excessive queues.  
- **Step 9: Tune and iterate.** If new bottlenecks emerge (e.g. network or DB delays), apply similar parallelization. For example, if writing results to a database is slow, add a bulk-write step or cache.

By converting the pipeline into independently scalable stages and applying parallelism judiciously, idle CPU/GPU time is minimized. For instance, the Oracle case study increased GPU utilization ~4× (from ~12% to 50%) simply by fixing upstream CPU bottlenecks【7†L59-L64】【7†L163-L172】. With careful orchestration, asynchronous I/O, and multi-worker processing, the phishing pipeline can similarly achieve much higher throughput. 

**References:** Proven techniques include asynchronous scraping to overlap I/O【20†L81-L90】【24†L974-L980】, multiprocessing for CPU-bound work, per-stage queues for decoupling【10†L468-L474】【7†L80-L89】, and GPU partitioning (MIG) for higher utilization【22†L49-L57】【26†L53-L61】. These strategies align with modern CI/CD and cloud practices (AWS, Kubernetes, Terraform) to build a robust, high-throughput phishing detection system.
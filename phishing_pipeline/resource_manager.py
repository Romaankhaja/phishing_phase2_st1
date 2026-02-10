import asyncio
import logging
import psutil
import torch

logger = logging.getLogger(__name__)

class ResourceMonitor:
    def __init__(self, cpu_threshold=90.0, ram_threshold=85.0, gpu_threshold=90.0, check_interval=1.0):
        self.cpu_threshold = cpu_threshold
        self.ram_threshold = ram_threshold
        self.gpu_threshold = gpu_threshold
        self.check_interval = check_interval
        self.gpu_available = torch.cuda.is_available()
        if self.gpu_available:
            self.device_name = torch.cuda.get_device_name(0)
            logger.info(f"ResourceMonitor: GPU detected: {self.device_name}")
        else:
            logger.info("ResourceMonitor: No GPU detected. Running in CPU-only mode.")

    def check_resources(self) -> bool:
        """
        Returns True if resources are available (usage is BELOW thresholds).
        Returns False if system is under heavy load.
        """
        # 1. Check CPU
        cpu_usage = psutil.cpu_percent(interval=None) # Non-blocking
        if cpu_usage > self.cpu_threshold:
            logger.debug(f"Throttling: High CPU usage ({cpu_usage}%)")
            return False

        # 2. Check RAM
        ram_usage = psutil.virtual_memory().percent
        if ram_usage > self.ram_threshold:
            logger.debug(f"Throttling: High RAM usage ({ram_usage}%)")
            return False

        # 3. Check GPU (if available)
        if self.gpu_available:
            try:
                # torch.cuda.mem_get_info() returns (free, total)
                free_mem, total_mem = torch.cuda.mem_get_info()
                used_mem_pct = ((total_mem - free_mem) / total_mem) * 100
                if used_mem_pct > self.gpu_threshold:
                    logger.debug(f"Throttling: High GPU memory usage ({used_mem_pct:.1f}%)")
                    return False
            except RuntimeError as e:
                # CUDA OOM during check means we should definitely throttle
                if "out of memory" in str(e).lower():
                    logger.warning("GPU exhausted during resource check, forcing throttle")
                    torch.cuda.empty_cache()  # Try to recover
                    return False
                logger.warning(f"Error checking GPU resources: {e}")
            except Exception as e:
                logger.warning(f"Error checking GPU resources: {e}")

        return True

    async def wait_for_resources(self):
        """
        Blocks asynchronously until resources are available.
        Actively clears GPU cache while waiting to help free memory.
        """
        wait_count = 0
        while not self.check_resources():
            wait_count += 1
            # Actively try to free GPU memory while waiting
            if self.gpu_available and wait_count % 3 == 0:
                try:
                    torch.cuda.empty_cache()
                    import gc
                    gc.collect()
                except Exception:
                    pass
            await asyncio.sleep(self.check_interval)

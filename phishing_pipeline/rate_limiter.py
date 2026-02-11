import asyncio
import time

class RateLimiter:
    """
    A simple async rate limiter.
    Ensures that we don't exceed a specified number of requests per minute.
    """
    def __init__(self, requests_per_minute=20):
        self.rate = requests_per_minute
        self.interval = 60.0 / self.rate
        self.last_request_time = 0
        self.lock = asyncio.Lock()

    async def acquire(self):
        """
        Wait until it's safe to make a request.
        """
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_request_time
            if elapsed < self.interval:
                sleep_time = self.interval - elapsed
                await asyncio.sleep(sleep_time)
            
            self.last_request_time = time.time()

    def reset(self):
        """Reset the rate limiter state."""
        self.last_request_time = 0

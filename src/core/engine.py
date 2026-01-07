import asyncio
import logging
from typing import List, Callable, Any, Coroutine
from .scanner import Scanner
from ..smb.client import SMBClient
from ..smb.session import SMBSession

logger = logging.getLogger(__name__)

class Engine:
    """Orchestrates the scanning and analysis process."""
    
    def __init__(self, concurrency: int = 10):
        self.concurrency = concurrency
        self.queue = asyncio.Queue()
        self.results = []

    async def worker(self, task_func: Callable[..., Coroutine[Any, Any, Any]]):
        """Generic worker to process tasks from the queue."""
        while True:
            target = await self.queue.get()
            try:
                result = await task_func(target)
                if result:
                    self.results.append(result)
            except Exception as e:
                logger.error(f"Error processing {target}: {e}")
            finally:
                self.queue.task_done()

    async def run_scan(self, targets: List[str], task_func: Callable[..., Coroutine[Any, Any, Any]]):
        """Runs the engine with multiple workers."""
        # Add targets to queue
        for target in targets:
            await self.queue.put(target)
            
        # Create workers
        workers = [asyncio.create_task(self.worker(task_func)) for _ in range(self.concurrency)]
        
        # Wait for all tasks to be processed
        await self.queue.join()
        
        # Cancel workers
        for worker in workers:
            worker.cancel()
            
        await asyncio.gather(*workers, return_exceptions=True)
        return self.results

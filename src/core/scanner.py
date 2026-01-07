import asyncio
import logging
import socket
from typing import List, AsyncGenerator, Optional
import ipaddress

logger = logging.getLogger(__name__)

class Scanner:
    """Asynchronous IP scanner to identify open SMB ports."""
    
    def __init__(self, port: int = 445, timeout: float = 1.0, concurrency: int = 100):
        self.port = port
        self.timeout = timeout
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)

    async def check_port(self, ip: str) -> Optional[str]:
        """Checks if a port is open on a given IP."""
        async with self.semaphore:
            try:
                # Use wait_for to enforce timeout on connection
                conn = asyncio.open_connection(ip, self.port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return ip
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception as e:
                logger.debug(f"Error checking {ip}:{self.port}: {e}")
                return None

    async def scan_range(self, network: str) -> AsyncGenerator[str, None]:
        """Scans a CIDR network range for open SMB ports."""
        try:
            net = ipaddress.ip_network(network, strict=False)
            tasks = [self.check_port(str(ip)) for ip in net.hosts()]
            
            # Use as_completed to yield results as they come
            for task in asyncio.as_completed(tasks):
                result = await task
                if result:
                    yield result
        except ValueError as e:
            logger.error(f"Invalid network range: {network} - {e}")

    async def scan_list(self, ips: List[str]) -> List[str]:
        """Scans a list of IPs for open SMB ports."""
        tasks = [self.check_port(ip) for ip in ips]
        results = await asyncio.gather(*tasks)
        return [ip for ip in results if ip]

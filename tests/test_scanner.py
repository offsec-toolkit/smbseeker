import pytest
import asyncio
from src.core.scanner import Scanner

@pytest.mark.asyncio
async def test_scanner_initialization():
    scanner = Scanner(concurrency=10)
    assert scanner.port == 445
    assert scanner.concurrency == 10

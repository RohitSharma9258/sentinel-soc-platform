import os

# Maximum size of the internal asyncio.Queue for packet buffering
QUEUE_MAXSIZE = int(os.getenv("QUEUE_MAXSIZE", "10000"))

# Redis connection parameters (used by processor, not directly here)
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# AYUSH WORK AREA
# Core Redis client for caching and queue backing
# Implements connection pooling, retry logic, and graceful error handling

import redis.asyncio as redis
from .config import settings
import logging

logger = logging.getLogger("ai_engine")

async def get_redis_client():
    """Get Redis client with connection pooling"""
    try:
        client = redis.Redis(
            host=settings.REDIS_HOST or 'localhost',
            port=int(settings.REDIS_PORT or 6379),
            password=settings.REDIS_PASSWORD,
            decode_responses=True,
            max_connections=20,
            socket_timeout=5,
            socket_connect_timeout=5,
        )
        
        # Test connection
        await client.ping()
        logger.info("Redis connection established successfully")
        return client
        
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {str(e)}")
        raise

async def close_redis_client(client):
    """Close Redis connection gracefully"""
    try:
        await client.aclose()
        logger.info("Redis connection closed")
    except Exception as e:
        logger.error(f"Error closing Redis connection: {str(e)}")
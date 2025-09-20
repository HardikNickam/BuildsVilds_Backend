
import redis.asyncio as redis
from app.core.config import settings
import logging
import json
from typing import Optional, Any

# Set up logging
logger = logging.getLogger(__name__)

# Global Redis client instance
redis_client: redis.Redis = None

async def connect_to_redis():
    global redis_client
    try:
        # Create Redis client from URL
        redis_client = redis.from_url(settings.redis_url)
        
        # Test the connection
        await redis_client.ping()
        logger.info("Successfully connected to Redis")
        
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        # For development, continue without Redis (you can implement fallbacks)
        redis_client = None
        raise e

async def close_redis_connection():
    global redis_client
    if redis_client:
        await redis_client.close()
        logger.info("Redis connection closed")

class RedisService:
    @staticmethod
    async def set_with_expiry(key: str, value: Any, expire_seconds: int):
        if not redis_client:
            return False
            
        try:
            # Convert value to JSON string for storage
            json_value = json.dumps(value) if not isinstance(value, str) else value
            await redis_client.setex(key, expire_seconds, json_value)
            return True
        except Exception as e:
            logger.error(f"Error setting Redis key {key}: {e}")
            return False
    
    @staticmethod
    async def get(key: str) -> Optional[Any]:
        if not redis_client:
            return None
            
        try:
            value = await redis_client.get(key)
            if value:
                # Try to decode JSON, fallback to string
                try:
                    return json.loads(value.decode('utf-8'))
                except json.JSONDecodeError:
                    return value.decode('utf-8')
            return None
        except Exception as e:
            logger.error(f"Error getting Redis key {key}: {e}")
            return None
    
    @staticmethod
    async def delete(key: str) -> bool:
        if not redis_client:
            return False
            
        try:
            result = await redis_client.delete(key)
            return result > 0
        except Exception as e:
            logger.error(f"Error deleting Redis key {key}: {e}")
            return False
    
    @staticmethod
    async def increment_with_expiry(key: str, expire_seconds: int = 60) -> int:
        if not redis_client:
            return 0
            
        try:
            # Use pipeline for atomic operation
            pipe = redis_client.pipeline()
            pipe.incr(key)  # Increment the key
            pipe.expire(key, expire_seconds)  # Set expiration
            results = await pipe.execute()
            return results[0]  # Return the incremented value
        except Exception as e:
            logger.error(f"Error incrementing Redis key {key}: {e}")
            return 0
    
    @staticmethod
    async def exists(key: str) -> bool:
        if not redis_client:
            return False
            
        try:
            result = await redis_client.exists(key)
            return result > 0
        except Exception as e:
            logger.error(f"Error checking Redis key {key}: {e}")
            return False

# Create global instance of the service
redis_service = RedisService()
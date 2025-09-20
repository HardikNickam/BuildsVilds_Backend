"""
Phase 2: Simple database connection setup.
"""

from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
import os
import logging

logger = logging.getLogger(__name__)

# Global database client
db_client: AsyncIOMotorClient = None

async def connect_to_database():
    """Connect to MongoDB and initialize Beanie."""
    global db_client
    
    try:
        # Get MongoDB URL from environment
        mongodb_url = os.getenv("MONGODB_URL", "mongodb://localhost:27017/buildvilds_test")
        
        # Create MongoDB client
        db_client = AsyncIOMotorClient(mongodb_url)
        
        # Test connection
        await db_client.admin.command('ping')
        logger.info("✅ Connected to MongoDB successfully")
        
        # Get database name from URL
        if "mongodb+srv://" in mongodb_url:
            # Atlas URL format
            db_name = mongodb_url.split('/')[-1].split('?')[0]
        else:
            # Local MongoDB format
            db_name = mongodb_url.split('/')[-1]
        
        database = db_client[db_name]
        
        # Import models
        from app.models.user import User
        from app.models.otp import OTP
        
        # Initialize Beanie
        await init_beanie(database=database, document_models=[User, OTP])
        logger.info("✅ Beanie ODM initialized successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to connect to MongoDB: {e}")
        # For development, we can continue without database
        raise e

async def close_database_connection():
    """Close database connection."""
    global db_client
    if db_client:
        db_client.close()
        logger.info("✅ Database connection closed")
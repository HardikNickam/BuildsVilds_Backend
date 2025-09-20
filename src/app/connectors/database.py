from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from app.core.config import settings
import logging


logger = logging.getLogger(__name__)

db_client: AsyncIOMotorClient = None

async def connect_to_database():
    global db_client
    try:
        db_client = AsyncIOMotorClient(settings.mongodb_url)
        await db_client.admin.command('ping')
        logger.info("✅ MongoDB connection successful!")
        database_name = settings.mongodb_url.split('/')[-1].split('?')[0]
        database = db_client[database_name]
        
        # Import all models that need to be registered with Beanie
        from app.models.user import User
        from app.models.refresh_token import RefreshToken
        from app.models.otp import OTP
        
        # Initialize Beanie with the database and all document models
        await init_beanie(
            database=database,
            document_models=[User, RefreshToken, OTP]
        )
        
        logger.info("Beanie ODM initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise e
    

async def close_databse_connection():
    global db_client
    if db_client:
        db_client.close()
        logger.info("MongoDB connection closed")

def get_databse():
    if not db_client:
        raise Exception("Databse not connected")
    database_name = settings.mongodb_url.split('/')[-1].split('?')[0]
    return db_client[database_name]

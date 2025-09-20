
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def test_mongo():
    client = AsyncIOMotorClient("mongodb+srv://hardiknikam7:HardikNikam@cluster0.lhj8elr.mongodb.net/")
    try:
        await client.admin.command('ping')
        print("✅ MongoDB connection successful!")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
    finally:
        client.close()

asyncio.run(test_mongo())
"""
Main entry point for production environment.
This file imports the FastAPI app and runs it with Uvicorn.
"""

import uvicorn
from app.utils.app import app

def main():
    """
    Main function to run the FastAPI application in production.
    """
    uvicorn.run(
        app,  # Use the app instance directly
        host="0.0.0.0",  # Listen on all interfaces
        port=8000,       # Default port
        log_level="info", # Set log level
        access_log=True   # Enable access logging
    )

if __name__ == "__main__":
    main()
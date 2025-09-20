"""
Development entry point with hot reloading.
This file runs the application in development mode with auto-reload.
"""

import uvicorn
import sys
import os

def main():
    """
    Main function to run the FastAPI application in development mode.
    """
    # Add the current directory (src) to Python path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = current_dir  # current_dir is already the src directory
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    
    uvicorn.run(
        "app.app:app",            # Fixed: correct module path (app.app, not app.utils.app)
        host="127.0.0.1",         # Localhost only for development
        port=8000,                # Default port
        reload=True,              # Enable auto-reload on code changes
        reload_dirs=[src_dir],    # Fixed: watch the correct src directory
        log_level="debug"         # More verbose logging for development
    )

if __name__ == "__main__":
    main()
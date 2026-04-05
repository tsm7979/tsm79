"""
TSM Layer Startup Script
=========================

Starts the AI Control Plane API server.
"""

import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    import uvicorn
    from gateway.api import app

    print("============================================================")
    print("TSM Layer - AI Control Plane v1.0")
    print("============================================================")
    print("Server: http://localhost:8000")
    print("Docs:   http://localhost:8000/docs")
    print("Health: http://localhost:8000/health")
    print("============================================================")
    print("")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )

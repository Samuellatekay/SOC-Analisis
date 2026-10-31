"""
Development runner for SOC Analisis Engine.
Usage:
    python run_dev.py
"""

import sys
import os
from pathlib import Path
import uvicorn

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

if __name__ == "__main__":
    print("=" * 70)
    print("   SOC Analisis & Priority Awareness Engine (Guo et al. 2026)")
    print("   Server running at: http://localhost:8000")
    print("   Swagger API docs:  http://localhost:8000/docs")
    print("=" * 70)

    uvicorn.run(
        "apps.api.app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )

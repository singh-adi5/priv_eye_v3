#!/usr/bin/env python3
"""
Convenience wrapper — trains the Random Forest model and writes model.pkl.

Usage (from repo root):
    # Direct:
    pip install -e api/
    MODEL_PATH=api/priveye_api/ml/model.pkl python scripts/train_model.py

    # Via docker compose (recommended for reproducible deps):
    docker compose run --rm api python -m priveye_api.ml.train

After training, copy the printed MODEL_SHA256 value into your .env file so the
API integrity-checks the artifact at startup.
"""

import os
import sys

# Add the api/ directory to sys.path so we can import priveye_api directly.
_HERE = os.path.dirname(__file__)
_API_DIR = os.path.join(_HERE, "..", "api")
sys.path.insert(0, os.path.abspath(_API_DIR))

# Default model path (override with MODEL_PATH env var).
if "MODEL_PATH" not in os.environ:
    default = os.path.join(_API_DIR, "priveye_api", "ml", "model.pkl")
    os.environ["MODEL_PATH"] = os.path.abspath(default)

# DATABASE_URL must be set for settings to load; provide a throw-away value for
# the training-only context (the train script never touches the DB).
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./train_temp.db")
os.environ.setdefault("JWT_SECRET", "training-only-not-for-production-use-padding-x")

from priveye_api.ml.train import train  # noqa: E402

if __name__ == "__main__":
    meta = train()
    print(
        "\n─────────────────────────────────────────────────────"
        "\nNext steps:"
        f"\n  1. Copy this line into your .env:"
        f"\n     MODEL_SHA256={meta['sha256']}"
        "\n  2. Restart the API:  docker compose restart api"
        "\n  3. Register a host and scan:  priveye-agent scan"
        "\n─────────────────────────────────────────────────────"
    )

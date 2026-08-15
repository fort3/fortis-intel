"""Fortis Intelligence Hub — Flask development server entry point."""

import sys
import os

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from app.web import create_app

app = create_app()

if __name__ == "__main__":
    print("\n=== Fortis Intelligence Hub ===")
    print("Starting Flask development server...")
    print("Access at: http://127.0.0.1:5000\n")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False,
        threaded=False,
    )

"""Fortis Intelligence Hub — Windows-optimized startup using Waitress."""

import sys
import os

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from app.web import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    print("\n=== Fortis Intelligence Hub ===")

    try:
        from waitress import serve

        print(f"Starting Waitress server on http://127.0.0.1:{port}")
        print("Press Ctrl+C to stop.\n")
        serve(app, host="127.0.0.1", port=port, threads=4)
    except ImportError:
        print("Waitress not installed, falling back to Flask dev server.")
        print(f"Access at: http://127.0.0.1:{port}\n")
        app.run(
            host="127.0.0.1",
            port=port,
            debug=True,
            use_reloader=False,
            threaded=False,
        )

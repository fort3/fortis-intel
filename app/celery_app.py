"""Celery application configuration for Fortis Intelligence Hub background task processing."""

import os
from celery import Celery
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Read configuration from environment
REDIS_URL = os.getenv("REDIS_URL", "")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL or "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL or "redis://localhost:6379/0")

def _redact_url(url: str) -> str:
    """Redact password from Redis URLs for safe logging."""
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(url)
    if parsed.password:
        replaced = parsed._replace(netloc=f"{parsed.username or ''}:***@{parsed.hostname}:{parsed.port or 6379}")
        return urlunparse(replaced)
    return url

# Debug logging (redacted)
print(f"[CELERY_INIT] REDIS_URL: {_redact_url(REDIS_URL)}")
print(f"[CELERY_INIT] CELERY_BROKER_URL: {_redact_url(CELERY_BROKER_URL)}")
print(f"[CELERY_INIT] CELERY_RESULT_BACKEND: {_redact_url(CELERY_RESULT_BACKEND)}")

# Create Celery app
celery_app = Celery(
    "fortis_hub",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
)

# Celery configuration
celery_app.conf.update(
    # Task execution settings
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,

    # Task routing
    task_routes={
        "app.forge.*": {"queue": "fortis_monitor"},
        "app.tasks.*": {"queue": "fortis_monitor"},
    },

    # Task time limits (5 minutes soft, 10 minutes hard)
    task_soft_time_limit=300,
    task_time_limit=600,

    # Result backend settings (keep results for 24 hours)
    result_expires=86400,

    # Worker settings
    worker_prefetch_multiplier=1,  # Only prefetch one task at a time
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks

    # Acknowledgment settings
    task_acks_late=True,  # Acknowledge task after completion
    task_reject_on_worker_lost=True,  # Reject task if worker dies

    # Celery Beat periodic tasks
    beat_schedule={
        "poll-all-monitors-every-5m": {
            "task": "app.tasks.poll_all_monitors",
            "schedule": 300.0,
        },
    },
)

# Auto-discover tasks in app.forge and app.tasks modules
celery_app.autodiscover_tasks(["app.forge", "app.tasks"])


if __name__ == "__main__":
    celery_app.start()

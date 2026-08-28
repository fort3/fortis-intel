"""Platform configurations and constants for Fortis Intelligence Hub."""

SOCIAL_PLATFORMS = {
    "twitter": {
        "name": "Twitter / X",
        "env_key": "TWITTER_BEARER_TOKEN",
        "rate_limit": {"requests": 300, "window_seconds": 900},
        "max_results_per_query": 200,
    },
    "reddit": {
        "name": "Reddit",
        "env_keys": ["REDDIT_CLIENT_ID", "REDDIT_CLIENT_SECRET"],
        "rate_limit": {"requests": 60, "window_seconds": 60},
        "max_results_per_query": 200,
    },
    "telegram": {
        "name": "Telegram",
        "env_keys": ["TELEGRAM_API_ID", "TELEGRAM_API_HASH"],
        "rate_limit": {"requests": 30, "window_seconds": 60},
        "max_results_per_query": 100,
    },
    "instagram": {
        "name": "Instagram",
        "env_key": "INSTAGRAM_ACCESS_TOKEN",
        "rate_limit": {"requests": 200, "window_seconds": 3600},
        "max_results_per_query": 100,
    },
    "youtube": {
        "name": "YouTube",
        "env_key": "YOUTUBE_API_KEY",
        "rate_limit": {"requests": 100, "window_seconds": 60},
        "max_results_per_query": 50,
    },
    "mastodon": {
        "name": "Mastodon",
        "env_keys": ["MASTODON_INSTANCE_URL", "MASTODON_ACCESS_TOKEN"],
        "rate_limit": {"requests": 300, "window_seconds": 300},
        "max_results_per_query": 200,
    },
    "facebook": {
        "name": "Facebook",
        "env_key": "FACEBOOK_ACCESS_TOKEN",
        "rate_limit": {"requests": 200, "window_seconds": 3600},
        "max_results_per_query": 100,
    },
    "tiktok": {
        "name": "TikTok",
        "env_key": "TIKTOK_API_KEY",
        "rate_limit": {"requests": 100, "window_seconds": 60},
        "max_results_per_query": 50,
    },
}

IDENTIFIER_TYPES = ["username", "email", "phone", "domain", "name", "ip", "keyword"]

INVESTIGATION_DEPTHS = {
    "quick": "API only — fast social media lookups",
    "standard": "API + web — social media plus web scraping",
    "deep": "All sources — comprehensive including metadata analysis",
}

SENSITIVITY_LEVELS = {
    "PUBLIC": {
        "label": "PUBLIC",
        "description": "No PII, general trends only",
        "color": "#22c55e",
    },
    "INTERNAL": {
        "label": "INTERNAL",
        "description": "Contains identifying details, organizational use",
        "color": "#8b5cf6",
    },
    "RESTRICTED": {
        "label": "RESTRICTED",
        "description": "Sensitive location or behavioral patterns",
        "color": "#f59e0b",
    },
    "CONFIDENTIAL": {
        "label": "CONFIDENTIAL",
        "description": "Could endanger if disclosed",
        "color": "#ef4444",
    },
}

GEO_SOURCES = {
    "exif": {"label": "EXIF GPS", "confidence_default": 0.95, "point_type": "exact"},
    "geotag": {"label": "Social Geotag", "confidence_default": 0.85, "point_type": "exact"},
    "ip": {"label": "IP Geolocation", "confidence_default": 0.5, "point_type": "approximate"},
    "checkin": {"label": "Check-in", "confidence_default": 0.9, "point_type": "exact"},
    "mention": {"label": "Text Mention", "confidence_default": 0.4, "point_type": "inferred"},
    "timezone": {"label": "Timezone Inference", "confidence_default": 0.3, "point_type": "inferred"},
    "vision_geolocation": {"label": "AI Vision Geo", "confidence_default": 0.55, "point_type": "inferred"},
    "geoclip": {"label": "GeoCLIP Embedding", "confidence_default": 0.45, "point_type": "inferred"},
}

SCENARIO_TYPES = {
    "pattern_of_life": "Daily/weekly behavioral patterns from posting data",
    "network_mapping": "Social graph and connection analysis",
    "location_prediction": "Probable future locations based on patterns",
    "influence_analysis": "Reach, engagement patterns, influence networks",
}

MONITOR_TYPES = ["keyword", "username", "hashtag", "location_radius", "telegram_channel"]

MONITOR_INTERVALS = [5, 15, 30, 60, 240]

ALERT_THRESHOLDS = {
    "all": "All findings",
    "high_confidence": "High confidence only",
    "geo_match": "Geo matches only",
}

ENTITY_NODE_TYPES = {
    "person": {"color": "#9b59b6", "label": "Person"},
    "organization": {"color": "#8b5cf6", "label": "Organization"},
    "location": {"color": "#22c55e", "label": "Location"},
    "account": {"color": "#bb6bd9", "label": "Account"},
    "domain": {"color": "#6b3fa0", "label": "Domain"},
    "event": {"color": "#f59e0b", "label": "Event"},
    "media": {"color": "#d946ef", "label": "Media"},
    "email": {"color": "#3b82f6", "label": "Email"},
    "credential": {"color": "#ef4444", "label": "Credential"},
    "infrastructure": {"color": "#f97316", "label": "Infrastructure"},
}

ENTITY_EDGE_TYPES = [
    "associated_with",
    "located_at",
    "posted_from",
    "linked_to",
    "alias_of",
    "member_of",
    "mentioned_by",
    "credential_link",
    "registered_on",
    "avatar_match",
    "same_email",
]

MAX_UPLOAD_SIZE_MB = 50
MAX_IMAGE_SIZE_MB = 20
MAX_BATCH_IDENTIFIERS = 100
MAX_CONCURRENT_BATCH_WORKERS = 8

FORTIS_ENDPOINTS = {
    "/ask",
    "/investigate",
    "/triangulate",
    "/batch-investigate",
    "/enrich",
    "/scenario",
    "/monitor/create",
    "/export/pdf",
    "/export/markdown",
    "/export/stix",
    "/export/csv",
    "/export/json",
    "/export/drive",
}

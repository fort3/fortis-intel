"""URL endpoint fuzzer for domain reconnaissance.

Probes common paths on a target domain to discover exposed endpoints,
admin panels, config files, API surfaces, and development artifacts.

This is an ACTIVE reconnaissance technique — it sends HTTP requests to the
target. Gated behind elevated_authorization in the investigation pipeline.

Uses the same curl_cffi stealth HTTP client as the rest of the platform.
"""

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urljoin

from app.http_client import create_session

log = logging.getLogger(__name__)

URL_FUZZ_ENABLED = os.getenv("URL_FUZZ_ENABLED", "true").lower() in ("1", "true", "yes")
URL_FUZZ_CONCURRENCY = int(os.getenv("URL_FUZZ_CONCURRENCY", "5"))
URL_FUZZ_TIMEOUT = float(os.getenv("URL_FUZZ_TIMEOUT", "8"))
URL_FUZZ_RATE_LIMIT = float(os.getenv("URL_FUZZ_RATE_LIMIT", "10"))

_INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503}

# ---------------------------------------------------------------------------
# Curated wordlist — tuned for OSINT recon, not exhaustive pentesting
# ---------------------------------------------------------------------------
FUZZ_PATHS = [
    # ── Admin & login panels ──────────────────────────────────────
    "/admin", "/admin/", "/administrator", "/login", "/signin",
    "/wp-admin", "/wp-login.php", "/wp-admin/install.php",
    "/cpanel", "/phpmyadmin", "/adminer", "/adminer.php",
    "/manager", "/manager/html", "/dashboard", "/panel",
    "/admin/login", "/admin/dashboard", "/cms", "/cms/admin",
    "/webmail", "/mail", "/owa",

    # ── API surfaces ─────────────────────────────────────────────
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/api/docs", "/api/swagger", "/api/openapi",
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui.html",
    "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/graphql", "/graphiql", "/graphql/console",
    "/api/graphql", "/api/health", "/api/status",
    "/api/config", "/api/info", "/api/version",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/api",
    "/health", "/healthz", "/health/check", "/status",
    "/readyz", "/livez", "/metrics",

    # ── Configuration & sensitive files ──────────────────────────
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.json", "/config.yaml", "/config.yml", "/config.xml",
    "/configuration.php", "/wp-config.php", "/wp-config.php.bak",
    "/settings.json", "/settings.py", "/settings.yaml",
    "/application.properties", "/application.yml",
    "/database.yml", "/database.json",
    "/credentials.json", "/secrets.json",
    "/web.config", "/Web.config",
    "/appsettings.json", "/appsettings.Development.json",
    "/composer.json", "/package.json", "/Gemfile",
    "/requirements.txt", "/Pipfile",
    "/.htaccess", "/.htpasswd",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/php.ini", "/phpinfo.php", "/info.php",

    # ── Version control & CI/CD artifacts ────────────────────────
    "/.git", "/.git/config", "/.git/HEAD", "/.git/index",
    "/.gitignore", "/.gitattributes",
    "/.svn", "/.svn/entries", "/.svn/wc.db",
    "/.hg", "/.hg/hgrc",
    "/.bzr",
    "/.gitlab-ci.yml", "/.github",
    "/Jenkinsfile", "/Dockerfile", "/docker-compose.yml",
    "/.circleci/config.yml",
    "/.travis.yml",

    # ── Backup & archive files ───────────────────────────────────
    "/backup", "/backup.sql", "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/database.sql", "/dump.sql",
    "/site.zip", "/www.zip", "/public.zip",
    "/backup.bak", "/old", "/archive",

    # ── Debug & development ──────────────────────────────────────
    "/debug", "/debug/", "/console", "/shell",
    "/_debug", "/__debug__",
    "/test", "/testing", "/dev", "/development",
    "/staging", "/stage",
    "/trace", "/trace.axd", "/elmah.axd",
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/beans", "/actuator/mappings", "/actuator/info",
    "/server-status", "/server-info",
    "/.well-known/security.txt", "/security.txt",
    "/humans.txt",

    # ── Common CMS paths ─────────────────────────────────────────
    "/wp-content", "/wp-includes", "/wp-json",
    "/wp-json/wp/v2/users", "/xmlrpc.php",
    "/wp-cron.php", "/wp-config.txt",
    "/joomla", "/administrator/index.php",
    "/drupal", "/user/login",
    "/ghost", "/ghost/api",

    # ── Error & info pages ───────────────────────────────────────
    "/404", "/500", "/error", "/errors",
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/sitemap_index.xml", "/sitemap.txt",
    "/BingSiteAuth.xml", "/google*.html",
    "/ads.txt", "/app-ads.txt",

    # ── Cloud & storage ──────────────────────────────────────────
    "/.aws/credentials", "/.aws/config",
    "/storage", "/uploads", "/upload",
    "/files", "/media", "/assets",
    "/static", "/public",
    "/s3", "/minio",

    # ── Common application paths ─────────────────────────────────
    "/account", "/accounts", "/profile", "/user", "/users",
    "/register", "/signup", "/reset-password", "/forgot-password",
    "/logout", "/signout",
    "/search", "/about", "/contact",
    "/terms", "/privacy", "/legal",
    "/docs", "/documentation", "/help",
    "/changelog", "/release-notes",

    # ── Server technologies ──────────────────────────────────────
    "/cgi-bin", "/cgi-bin/", "/cgi-sys",
    "/fcgi-bin",
    "/server", "/proxy",
    "/nginx.conf", "/httpd.conf",

    # ── Monitoring & ops ─────────────────────────────────────────
    "/grafana", "/kibana", "/prometheus",
    "/nagios", "/zabbix", "/munin",
    "/jenkins", "/hudson", "/bamboo",
    "/sonar", "/sonarqube",
    "/sentry",

    # ── Auth & SSO ───────────────────────────────────────────────
    "/oauth", "/oauth2", "/auth", "/authorize",
    "/saml", "/sso", "/cas", "/adfs",
    "/.well-known/openid-configuration",
    "/token", "/callback",
]


def _classify_finding(path: str, status: int, headers: dict) -> str:
    """Classify a discovered endpoint by risk level."""
    content_type = headers.get("content-type", "").lower()

    critical_paths = {
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/config", "/.git/HEAD", "/.git/index",
        "/.aws/credentials", "/.aws/config",
        "/credentials.json", "/secrets.json", "/.htpasswd",
        "/backup.sql", "/db.sql", "/database.sql", "/dump.sql",
        "/wp-config.php.bak", "/wp-config.txt",
        "/server-status", "/server-info",
        "/actuator/env",
        "/phpinfo.php", "/info.php",
        "/.svn/wc.db",
    }

    high_paths = {
        "/admin", "/admin/", "/administrator", "/wp-admin",
        "/phpmyadmin", "/adminer", "/adminer.php",
        "/cpanel", "/console", "/shell",
        "/graphiql", "/graphql/console",
        "/swagger-ui", "/swagger-ui.html",
        "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/api/config", "/wp-json/wp/v2/users",
        "/xmlrpc.php", "/elmah.axd", "/trace.axd",
        "/actuator/beans", "/actuator/mappings",
        "/.gitlab-ci.yml", "/Jenkinsfile", "/Dockerfile",
        "/docker-compose.yml",
        "/backup", "/backup.zip", "/backup.tar.gz",
        "/site.zip", "/www.zip", "/public.zip",
    }

    lp = path.lower()

    if status == 200 and lp in critical_paths:
        return "CRITICAL"
    if status == 200 and lp in high_paths:
        return "HIGH"
    if status == 200 and ("sql" in lp or "backup" in lp or "dump" in lp):
        return "HIGH"
    if status in (200, 204) and "json" in content_type and lp.startswith("/api"):
        return "MEDIUM"
    if status == 403 and lp in critical_paths:
        return "MEDIUM"
    if status in (401, 403):
        return "LOW"
    if status in (301, 302, 307, 308):
        return "INFO"
    if status == 200:
        return "MEDIUM"
    return "INFO"


def fuzz_domain(
    domain: str,
    paths: list[str] | None = None,
    schemes: list[str] | None = None,
) -> dict[str, Any]:
    """Probe *domain* for common exposed endpoints.

    Returns a dict with ``domain``, ``endpoints_found``, ``total_probed``,
    ``by_severity``, and ``findings`` (list of per-path results).
    """
    if not URL_FUZZ_ENABLED:
        return {
            "domain": domain,
            "enabled": False,
            "endpoints_found": 0,
            "findings": [],
        }

    target_paths = paths or FUZZ_PATHS
    target_schemes = schemes or ["https", "http"]

    session = create_session(timeout=URL_FUZZ_TIMEOUT)
    findings: list[dict[str, Any]] = []
    probed = 0
    interval = 1.0 / URL_FUZZ_RATE_LIMIT if URL_FUZZ_RATE_LIMIT > 0 else 0

    log.info("URL fuzzing %s: %d paths, concurrency=%d", domain, len(target_paths), URL_FUZZ_CONCURRENCY)

    def _probe(path: str) -> dict[str, Any] | None:
        for scheme in target_schemes:
            base = f"{scheme}://{domain}"
            url = urljoin(base, path)
            try:
                resp = session.get(
                    url,
                    allow_redirects=False,
                    timeout=URL_FUZZ_TIMEOUT,
                )
                status = resp.status_code
                if status not in _INTERESTING_STATUS:
                    return None

                resp_headers = {}
                if hasattr(resp.headers, "items"):
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                else:
                    resp_headers = dict(resp.headers)

                content_length = int(resp_headers.get("content-length", 0))
                content_type = resp_headers.get("content-type", "")
                location = resp_headers.get("location", "")
                server = resp_headers.get("server", "")

                severity = _classify_finding(path, status, resp_headers)

                return {
                    "path": path,
                    "url": url,
                    "status": status,
                    "content_type": content_type.split(";")[0].strip() if content_type else "",
                    "content_length": content_length,
                    "redirect_to": location,
                    "server": server,
                    "severity": severity,
                }
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=URL_FUZZ_CONCURRENCY) as pool:
        future_map = {}
        for path in target_paths:
            if interval > 0:
                time.sleep(interval)
            future_map[pool.submit(_probe, path)] = path

        for future in as_completed(future_map):
            probed += 1
            try:
                result = future.result()
                if result:
                    findings.append(result)
            except Exception:
                pass

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 5), f["path"]))

    by_severity = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    log.info(
        "URL fuzzing %s complete: %d/%d endpoints found (%s)",
        domain, len(findings), probed,
        ", ".join(f"{k}:{v}" for k, v in sorted(by_severity.items())),
    )

    return {
        "domain": domain,
        "enabled": True,
        "endpoints_found": len(findings),
        "total_probed": probed,
        "by_severity": by_severity,
        "findings": findings,
    }

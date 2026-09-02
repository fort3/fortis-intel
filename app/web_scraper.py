"""Web scraping and lookup utilities for Fortis Intelligence Hub."""

import logging
import os
from typing import Any
from urllib.parse import quote, urlparse

import dns.resolver
import feedparser
import whois
from newsapi import NewsApiClient

from app.http_client import create_session

try:
    import shodan

    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False

log = logging.getLogger(__name__)


class WebScraper:
    """Web scraping, RSS parsing, and domain intelligence utilities."""

    def __init__(self):
        self._newsapi_key = os.environ.get("NEWSAPI_KEY")
        self._newsapi: NewsApiClient | None = None
        if self._newsapi_key:
            self._newsapi = NewsApiClient(api_key=self._newsapi_key)
            log.info("WebScraper initialised — NewsAPI configured")
        else:
            log.info("WebScraper initialised — NewsAPI NOT configured (NEWSAPI_KEY not set)")

        # Shodan integration
        self._shodan_key = os.environ.get("SHODAN_API_KEY")
        self._shodan_api: Any | None = None
        if self._shodan_key:
            if HAS_SHODAN:
                self._shodan_api = shodan.Shodan(self._shodan_key)
                log.info("Shodan API configured")
            else:
                log.warning("SHODAN_API_KEY is set but 'shodan' library is not installed")
        else:
            log.info("Shodan API NOT configured (SHODAN_API_KEY not set)")

        # VirusTotal integration
        self._virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if self._virustotal_key:
            log.info("VirusTotal API configured")
        else:
            log.info("VirusTotal API NOT configured (VIRUSTOTAL_API_KEY not set)")

        self._http = create_session(pool_connections=4, pool_maxsize=6)

    def parse_rss_feed(self, feed_url: str) -> list[dict[str, Any]]:
        try:
            feed = feedparser.parse(feed_url)
            if feed.bozo and not feed.entries:
                log.error("Failed to parse RSS feed %r: %s", feed_url, feed.bozo_exception)
                return []
            entries: list[dict[str, Any]] = []
            for entry in feed.entries:
                entries.append({
                    "title": getattr(entry, "title", ""),
                    "link": getattr(entry, "link", ""),
                    "published": getattr(entry, "published", ""),
                    "summary": getattr(entry, "summary", ""),
                    "author": getattr(entry, "author", ""),
                })
            return entries
        except Exception:
            log.exception("Unexpected error parsing RSS feed %r", feed_url)
            return []

    NEWS_RSS_FEEDS: list[dict[str, str]] = [
        {"name": "BBC News",      "url": "https://feeds.bbci.co.uk/news/rss.xml"},
        {"name": "BBC World",     "url": "https://feeds.bbci.co.uk/news/world/rss.xml"},
        {"name": "CNN Top",       "url": "http://rss.cnn.com/rss/edition.rss"},
        {"name": "CNN World",     "url": "http://rss.cnn.com/rss/edition_world.rss"},
        {"name": "Reuters World", "url": "https://www.reutersagency.com/feed/?taxonomy=best-sectors&post_type=best"},
        {"name": "AP News",       "url": "https://rsshub.app/apnews/topics/apf-topnews"},
        {"name": "Al Jazeera",    "url": "https://www.aljazeera.com/xml/rss/all.xml"},
    ]

    def _fetch_news_rss(self, query: str, limit: int = 30) -> list[dict[str, Any]]:
        """Query curated RSS feeds and filter entries by keyword match."""
        q_lower = query.lower()
        q_words = q_lower.split()
        articles: list[dict[str, Any]] = []
        seen_urls: set[str] = set()

        for feed_info in self.NEWS_RSS_FEEDS:
            try:
                feed = feedparser.parse(feed_info["url"])
                for entry in feed.entries:
                    title = getattr(entry, "title", "") or ""
                    summary = getattr(entry, "summary", "") or ""
                    link = getattr(entry, "link", "") or ""

                    haystack = f"{title} {summary}".lower()
                    if not any(w in haystack for w in q_words):
                        continue
                    if link in seen_urls:
                        continue
                    seen_urls.add(link)

                    articles.append({
                        "title": title,
                        "url": link,
                        "source": feed_info["name"],
                        "published": getattr(entry, "published", ""),
                        "snippet": summary[:300],
                    })
                    if len(articles) >= limit:
                        return articles
            except Exception:
                log.debug("RSS feed %s unavailable, skipping", feed_info["name"])

        return articles

    def fetch_news(
        self,
        query: str,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        articles: list[dict[str, Any]] = []
        seen_urls: set[str] = set()

        # Layer 1: NewsAPI (if configured)
        if self._newsapi:
            try:
                params: dict[str, Any] = {"q": query, "language": "en", "sort_by": "relevancy"}
                if date_from:
                    params["from_param"] = date_from
                if date_to:
                    params["to"] = date_to
                response = self._newsapi.get_everything(**params)
                for article in response.get("articles", []):
                    source = article.get("source") or {}
                    url = article.get("url", "")
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    articles.append({
                        "title": article.get("title", ""),
                        "url": url,
                        "source": source.get("name", ""),
                        "published": article.get("publishedAt", ""),
                        "snippet": article.get("description", ""),
                    })
            except Exception:
                log.exception("NewsAPI error for query=%r, falling back to RSS", query)

        # Layer 2: curated RSS feeds (BBC, CNN, Reuters, AP, Al Jazeera)
        try:
            rss_cap = max(10, 30 - len(articles))
            for item in self._fetch_news_rss(query, limit=rss_cap):
                if item["url"] not in seen_urls:
                    seen_urls.add(item["url"])
                    articles.append(item)
        except Exception:
            log.exception("RSS news fetch failed for query=%r", query)

        if not articles:
            log.info("No news found for query=%r (NewsAPI %s)",
                     query, "configured" if self._newsapi else "not configured")
        return articles

    def whois_lookup(self, domain: str) -> dict[str, Any]:
        try:
            w = whois.whois(domain)
            raw_text = w.text if hasattr(w, "text") else str(w)

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            creation = str(creation) if creation else ""

            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            expiration = str(expiration) if expiration else ""

            name_servers = w.name_servers or []
            if isinstance(name_servers, str):
                name_servers = [name_servers]
            name_servers = [ns.lower() for ns in name_servers]

            registrant = ""
            if hasattr(w, "org") and w.org:
                registrant = w.org
            elif hasattr(w, "name") and w.name:
                registrant = w.name

            return {
                "registrar": w.registrar or "",
                "creation_date": creation,
                "expiration_date": expiration,
                "name_servers": sorted(set(name_servers)),
                "registrant": registrant,
                "raw": raw_text,
            }
        except Exception:
            log.exception("WHOIS lookup failed for %r", domain)
            return {
                "registrar": "",
                "creation_date": "",
                "expiration_date": "",
                "name_servers": [],
                "registrant": "",
                "raw": "",
            }

    def dns_lookup(self, domain: str) -> dict[str, Any]:
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]
        results: dict[str, list[str]] = {rt: [] for rt in record_types}
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    if rtype == "MX":
                        results[rtype].append(f"{rdata.preference} {rdata.exchange}")
                    elif rtype == "TXT":
                        results[rtype].append(
                            b"".join(rdata.strings).decode("utf-8", errors="replace")
                        )
                    elif rtype == "SOA":
                        results[rtype].append(
                            f"{rdata.mname} {rdata.rname} serial={rdata.serial}"
                        )
                    else:
                        results[rtype].append(str(rdata))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                log.debug("No %s records for %r", rtype, domain)
            except Exception:
                log.exception("DNS %s lookup failed for %r", rtype, domain)
        return results

    def check_robots_txt(self, url: str) -> dict[str, Any]:
        empty: dict[str, Any] = {
            "allowed": [],
            "disallowed": [],
            "sitemaps": [],
            "crawl_delay": None,
        }
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            resp = self._http.get(robots_url, timeout=10)
            if resp.status_code != 200:
                log.warning("robots.txt returned HTTP %d for %r", resp.status_code, robots_url)
                return empty

            allowed: list[str] = []
            disallowed: list[str] = []
            sitemaps: list[str] = []
            crawl_delay: float | None = None

            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                directive, _, value = line.partition(":")
                directive = directive.strip().lower()
                value = value.strip()
                if directive == "allow":
                    allowed.append(value)
                elif directive == "disallow":
                    disallowed.append(value)
                elif directive == "sitemap":
                    sitemaps.append(value)
                elif directive == "crawl-delay":
                    try:
                        crawl_delay = float(value)
                    except ValueError:
                        pass

            return {
                "allowed": allowed,
                "disallowed": disallowed,
                "sitemaps": sitemaps,
                "crawl_delay": crawl_delay,
            }
        except Exception:
            log.exception("Failed to fetch/parse robots.txt for %r", url)
            return empty

    # ------------------------------------------------------------------
    # DNSdumpster / HackerTarget API
    # ------------------------------------------------------------------

    _HACKERTARGET_BASE = "https://api.hackertarget.com"

    def _hackertarget_get(self, endpoint: str, query: str) -> str | None:
        try:
            resp = self._http.get(
                f"{self._HACKERTARGET_BASE}/{endpoint}/",
                params={"q": query},
                timeout=20,
            )
            if resp.status_code != 200:
                log.debug("HackerTarget %s returned %d", endpoint, resp.status_code)
                return None
            text = resp.text.strip()
            if text.startswith("error") or "API count exceeded" in text:
                log.warning("HackerTarget %s: %s", endpoint, text[:120])
                return None
            return text
        except Exception as exc:
            log.error("HackerTarget %s failed: %s", endpoint, exc)
            return None

    def dnsdumpster_lookup(self, domain: str) -> dict[str, Any]:
        """Subdomain enumeration and host discovery via HackerTarget API.

        Returns subdomains with their resolved IPs, reverse DNS entries,
        and basic HTTP header probes.
        """
        result: dict[str, Any] = {
            "domain": domain,
            "subdomains": [],
            "dns_records": {},
            "reverse_dns": [],
        }

        raw = self._hackertarget_get("hostsearch", domain)
        if raw:
            for line in raw.splitlines():
                parts = line.split(",", 1)
                if len(parts) == 2:
                    hostname, ip = parts[0].strip(), parts[1].strip()
                    result["subdomains"].append({
                        "hostname": hostname,
                        "ip": ip,
                    })

        dns_raw = self._hackertarget_get("dnslookup", domain)
        if dns_raw:
            records: dict[str, list[str]] = {}
            for line in dns_raw.splitlines():
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    rtype = parts[1].strip().upper()
                    rdata = parts[2].strip()
                    records.setdefault(rtype, []).append(rdata)
            result["dns_records"] = records

        log.info("DNSdumpster lookup for %r: %d subdomains found",
                 domain, len(result["subdomains"]))
        return result

    def reverse_ip_lookup(self, ip: str) -> list[str]:
        """Find domains hosted on the same IP address."""
        raw = self._hackertarget_get("reverseiplookup", ip)
        if not raw:
            return []
        domains = [line.strip() for line in raw.splitlines() if line.strip()]
        log.info("Reverse IP lookup for %s: %d domains", ip, len(domains))
        return domains

    def reverse_dns_lookup(self, ip: str) -> str:
        """PTR record / reverse DNS for an IP address."""
        raw = self._hackertarget_get("reversedns", ip)
        if not raw:
            return ""
        return raw.splitlines()[0].strip() if raw.strip() else ""

    def http_headers_lookup(self, domain: str) -> dict[str, str]:
        """Fetch HTTP response headers for a target domain."""
        raw = self._hackertarget_get("httpheaders", domain)
        if not raw:
            return {}
        headers: dict[str, str] = {}
        for line in raw.splitlines():
            if ": " in line:
                key, _, val = line.partition(": ")
                headers[key.strip()] = val.strip()
        return headers

    # ------------------------------------------------------------------
    # Shodan integration
    # ------------------------------------------------------------------

    def shodan_lookup(self, ip_or_domain: str) -> dict[str, Any]:
        """Query Shodan for host/service information.

        For IP addresses, calls ``api.host(ip)``.
        For domain strings, calls ``api.search(domain)``.

        Returns a normalised dict with host details and a ``services`` list,
        or an empty dict when the API key is missing or an error occurs.
        """
        if not self._shodan_api:
            log.warning("Shodan API not configured — set SHODAN_API_KEY environment variable")
            return {}

        try:
            # Determine whether the input looks like an IP address
            is_ip = False
            try:
                import ipaddress

                ipaddress.ip_address(ip_or_domain)
                is_ip = True
            except ValueError:
                pass

            if is_ip:
                host = self._shodan_api.host(ip_or_domain)
                services: list[dict[str, Any]] = []
                for item in host.get("data", []):
                    services.append({
                        "port": item.get("port"),
                        "transport": item.get("transport", "tcp"),
                        "product": item.get("product", ""),
                        "version": item.get("version", ""),
                    })
                return {
                    "ip": host.get("ip_str", ip_or_domain),
                    "hostnames": host.get("hostnames", []),
                    "ports": host.get("ports", []),
                    "vulns": host.get("vulns", []),
                    "os": host.get("os", ""),
                    "org": host.get("org", ""),
                    "isp": host.get("isp", ""),
                    "country": host.get("country_name", ""),
                    "city": host.get("city", ""),
                    "last_update": host.get("last_update", ""),
                    "services": services,
                }
            else:
                # Domain search — aggregate first-page results
                results = self._shodan_api.search(ip_or_domain)
                all_ports: list[int] = []
                all_hostnames: list[str] = []
                services = []
                first_ip = ""
                for match in results.get("matches", []):
                    if not first_ip:
                        first_ip = match.get("ip_str", "")
                    all_ports.append(match.get("port", 0))
                    all_hostnames.extend(match.get("hostnames", []))
                    services.append({
                        "port": match.get("port"),
                        "transport": match.get("transport", "tcp"),
                        "product": match.get("product", ""),
                        "version": match.get("version", ""),
                    })
                return {
                    "ip": first_ip,
                    "hostnames": sorted(set(all_hostnames)),
                    "ports": sorted(set(all_ports)),
                    "vulns": [],
                    "os": "",
                    "org": "",
                    "isp": "",
                    "country": "",
                    "city": "",
                    "last_update": "",
                    "services": services,
                }
        except Exception:
            log.exception("Shodan lookup failed for %r", ip_or_domain)
            return {}

    # ------------------------------------------------------------------
    # VirusTotal integration
    # ------------------------------------------------------------------

    def virustotal_lookup(
        self,
        indicator: str,
        indicator_type: str = "domain",
    ) -> dict[str, Any]:
        """Query the VirusTotal v3 API for reputation data.

        *indicator_type* must be one of ``"domain"``, ``"ip"``, ``"hash"``,
        or ``"url"``.

        Returns a normalised dict with analysis stats or an empty dict when
        the API key is missing or an error occurs.
        """
        if not self._virustotal_key:
            log.warning("VirusTotal API not configured — set VIRUSTOTAL_API_KEY environment variable")
            return {}

        base = "https://www.virustotal.com/api/v3"
        headers = {"x-apikey": self._virustotal_key}

        try:
            if indicator_type == "domain":
                resp = self._http.get(f"{base}/domains/{quote(indicator, safe='')}", headers=headers, timeout=15)
            elif indicator_type == "ip":
                resp = self._http.get(f"{base}/ip_addresses/{quote(indicator, safe='')}", headers=headers, timeout=15)
            elif indicator_type == "hash":
                resp = self._http.get(f"{base}/files/{quote(indicator, safe='')}", headers=headers, timeout=15)
            elif indicator_type == "url":
                # URL analysis requires a POST first, then a GET on the analysis
                submit_resp = self._http.post(
                    f"{base}/urls",
                    headers=headers,
                    data={"url": indicator},
                    timeout=15,
                )
                submit_resp.raise_for_status()
                analysis_id = submit_resp.json()["data"]["id"]
                resp = self._http.get(
                    f"{base}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=15,
                )
            else:
                log.error("Unsupported VirusTotal indicator_type %r", indicator_type)
                return {}

            resp.raise_for_status()
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})

            stats = attrs.get("last_analysis_stats", {})
            return {
                "indicator": indicator,
                "type": indicator_type,
                "reputation": attrs.get("reputation", 0),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "last_analysis_date": attrs.get("last_analysis_date", ""),
                "tags": attrs.get("tags", []),
                "categories": attrs.get("categories", {}),
            }
        except Exception:
            log.exception("VirusTotal lookup failed for %r (type=%s)", indicator, indicator_type)
            return {}

    # ------------------------------------------------------------------
    # crt.sh — Certificate Transparency (free, no API key)
    # ------------------------------------------------------------------

    def crtsh_lookup(self, domain: str) -> dict[str, Any]:
        """Query crt.sh for SSL/TLS certificates issued for a domain.

        Returns subdomains, issuers, and certificate timeline. No API key required.
        """
        try:
            resp = self._http.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=15,
            )
            if resp.status_code != 200:
                return {}

            entries = resp.json()
            subdomains = set()
            issuers = set()
            certs = []

            for entry in entries[:500]:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and name != domain and not name.startswith("*"):
                        subdomains.add(name)

                issuer = entry.get("issuer_name", "")
                if issuer:
                    issuers.add(issuer)

                certs.append({
                    "id": entry.get("id"),
                    "common_name": entry.get("common_name", ""),
                    "name_value": name_value,
                    "issuer": issuer,
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                })

            log.info("crt.sh lookup for %s: %d certs, %d subdomains",
                     domain, len(certs), len(subdomains))

            return {
                "domain": domain,
                "total_certs": len(entries),
                "subdomains": sorted(subdomains)[:100],
                "issuers": sorted(issuers),
                "recent_certs": certs[:20],
            }
        except Exception:
            log.exception("crt.sh lookup failed for %r", domain)
            return {}

    # ------------------------------------------------------------------
    # AbuseIPDB — IP reputation (free tier: 1000 checks/day)
    # ------------------------------------------------------------------

    def abuseipdb_check(self, ip: str) -> dict[str, Any]:
        """Check an IP address against AbuseIPDB.

        Requires ABUSEIPDB_API_KEY env var. Free tier allows 1000 checks/day.
        """
        api_key = os.environ.get("ABUSEIPDB_API_KEY")
        if not api_key:
            return {}

        try:
            resp = self._http.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            log.info("AbuseIPDB check for %s: score=%d, reports=%d",
                     ip, data.get("abuseConfidenceScore", 0),
                     data.get("totalReports", 0))

            return {
                "ip": ip,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "usage_type": data.get("usageType", ""),
                "last_reported": data.get("lastReportedAt", ""),
            }
        except Exception:
            log.exception("AbuseIPDB check failed for %r", ip)
            return {}

    # ------------------------------------------------------------------
    # AlienVault OTX — Threat intelligence (free, 10K requests/hour)
    # ------------------------------------------------------------------

    def otx_lookup(self, indicator: str, indicator_type: str = "domain") -> dict[str, Any]:
        """Query AlienVault OTX for threat intelligence.

        indicator_type: 'domain', 'ip', 'hostname', 'url', 'hash'
        Requires OTX_API_KEY env var. Free tier: 10,000 requests/hour.
        """
        api_key = os.environ.get("OTX_API_KEY")
        if not api_key:
            return {}

        type_map = {
            "domain": ("domain", "general"),
            "ip": ("IPv4", "general"),
            "hostname": ("hostname", "general"),
            "hash": ("file", "general"),
        }
        section_info = type_map.get(indicator_type)
        if not section_info:
            return {}

        otx_type, section = section_info

        try:
            base = "https://otx.alienvault.com/api/v1"
            headers = {"X-OTX-API-KEY": api_key}

            general_resp = self._http.get(
                f"{base}/indicators/{otx_type}/{quote(indicator, safe='')}/{section}",
                headers=headers,
                timeout=15,
            )
            general_resp.raise_for_status()
            general = general_resp.json()

            result = {
                "indicator": indicator,
                "type": indicator_type,
                "pulse_count": general.get("pulse_info", {}).get("count", 0),
                "reputation": general.get("reputation", 0),
                "country": general.get("country_name", ""),
                "asn": general.get("asn", ""),
            }

            pulses = general.get("pulse_info", {}).get("pulses", [])
            result["pulses"] = [
                {
                    "name": p.get("name", ""),
                    "description": p.get("description", "")[:200],
                    "created": p.get("created", ""),
                    "tags": p.get("tags", [])[:10],
                    "adversary": p.get("adversary", ""),
                    "tlp": p.get("TLP", ""),
                }
                for p in pulses[:10]
            ]

            result["tags"] = list(set(
                tag for p in pulses[:20] for tag in p.get("tags", [])
            ))[:30]

            log.info("OTX lookup for %s (%s): %d pulses, reputation=%s",
                     indicator, indicator_type,
                     result["pulse_count"], result["reputation"])

            return result
        except Exception:
            log.exception("OTX lookup failed for %r (type=%s)", indicator, indicator_type)
            return {}

    # ------------------------------------------------------------------
    # Hunter.io — Email finder & domain search (free: 25 searches/month)
    # ------------------------------------------------------------------

    def hunter_domain_search(self, domain: str) -> dict[str, Any]:
        """Find email addresses associated with a domain via Hunter.io.

        Requires HUNTER_API_KEY env var. Free tier: 25 searches/month.
        """
        api_key = os.environ.get("HUNTER_API_KEY")
        if not api_key:
            return {}

        try:
            resp = self._http.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": domain, "api_key": api_key, "limit": 20},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            emails = []
            for e in data.get("emails", []):
                emails.append({
                    "email": e.get("value", ""),
                    "type": e.get("type", ""),
                    "confidence": e.get("confidence", 0),
                    "first_name": e.get("first_name", ""),
                    "last_name": e.get("last_name", ""),
                    "position": e.get("position", ""),
                    "department": e.get("department", ""),
                })

            log.info("Hunter.io domain search for %s: %d emails found", domain, len(emails))

            return {
                "domain": domain,
                "organization": data.get("organization", ""),
                "email_pattern": data.get("pattern", ""),
                "emails": emails,
                "total": data.get("total", 0),
            }
        except Exception:
            log.exception("Hunter.io domain search failed for %r", domain)
            return {}

    def hunter_email_verify(self, email: str) -> dict[str, Any]:
        """Verify an email address via Hunter.io.

        Requires HUNTER_API_KEY env var.
        """
        api_key = os.environ.get("HUNTER_API_KEY")
        if not api_key:
            return {}

        try:
            resp = self._http.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": email, "api_key": api_key},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            return {
                "email": email,
                "status": data.get("status", ""),
                "result": data.get("result", ""),
                "score": data.get("score", 0),
                "disposable": data.get("disposable", False),
                "webmail": data.get("webmail", False),
                "mx_records": data.get("mx_records", False),
                "smtp_server": data.get("smtp_server", False),
            }
        except Exception:
            log.exception("Hunter.io email verify failed for %r", email)
            return {}

    # ------------------------------------------------------------------
    # EmailRep — Email reputation (free: 1000 checks/day, no key needed for basic)
    # ------------------------------------------------------------------

    def emailrep_check(self, email: str) -> dict[str, Any]:
        """Check email reputation via EmailRep.io.

        Free tier: basic info without API key. With EMAILREP_API_KEY: full data.
        """
        try:
            headers = {"User-Agent": "Fortis Intelligence Hub OSINT Platform"}
            api_key = os.environ.get("EMAILREP_API_KEY")
            if api_key:
                headers["Key"] = api_key

            resp = self._http.get(
                f"https://emailrep.io/{quote(email, safe='')}",
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()

            details = data.get("details", {})
            return {
                "email": email,
                "reputation": data.get("reputation", ""),
                "suspicious": data.get("suspicious", False),
                "references": data.get("references", 0),
                "blacklisted": details.get("blacklisted", False),
                "malicious_activity": details.get("malicious_activity", False),
                "credentials_leaked": details.get("credentials_leaked", False),
                "data_breach": details.get("data_breach", False),
                "first_seen": details.get("first_seen", ""),
                "last_seen": details.get("last_seen", ""),
                "domain_exists": details.get("domain_exists", True),
                "deliverable": details.get("deliverable", True),
                "free_provider": details.get("free_provider", False),
                "disposable": details.get("disposable", False),
                "spam": details.get("spam", False),
                "profiles": details.get("profiles", []),
            }
        except Exception:
            log.exception("EmailRep check failed for %r", email)
            return {}

    # ------------------------------------------------------------------
    # Numverify — Phone number validation (free: 100 requests/month)
    # ------------------------------------------------------------------

    def numverify_lookup(self, phone: str) -> dict[str, Any]:
        """Validate and geolocate a phone number via Numverify.

        Requires NUMVERIFY_API_KEY env var. Free tier: 100 requests/month.
        """
        api_key = os.environ.get("NUMVERIFY_API_KEY")
        if not api_key:
            return {}

        try:
            resp = self._http.get(
                "https://apilayer.net/api/validate",
                params={"access_key": api_key, "number": phone},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()

            if not data.get("valid"):
                return {"phone": phone, "valid": False}

            log.info("Numverify lookup for %s: %s, %s %s",
                     phone, data.get("carrier", "?"),
                     data.get("country_name", "?"), data.get("location", "?"))

            return {
                "phone": phone,
                "valid": True,
                "local_format": data.get("local_format", ""),
                "international_format": data.get("international_format", ""),
                "country_prefix": data.get("country_prefix", ""),
                "country_code": data.get("country_code", ""),
                "country_name": data.get("country_name", ""),
                "location": data.get("location", ""),
                "carrier": data.get("carrier", ""),
                "line_type": data.get("line_type", ""),
            }
        except Exception:
            log.exception("Numverify lookup failed for %r", phone)
            return {}

    # ── SecurityTrails ────────────────────────────────────────────

    def securitytrails_domain(self, domain: str) -> dict[str, Any]:
        """Fetch DNS history, subdomains, and associated domains via SecurityTrails.

        Requires SECURITYTRAILS_API_KEY env var. Free tier: 50 queries/month.
        """
        api_key = os.environ.get("SECURITYTRAILS_API_KEY")
        if not api_key:
            return {}

        headers = {"APIKEY": api_key, "Accept": "application/json"}
        base = "https://api.securitytrails.com/v1"
        result: dict[str, Any] = {"domain": domain}

        try:
            detail = self._http.get(
                f"{base}/domain/{domain}",
                headers=headers, timeout=12,
            )
            detail.raise_for_status()
            d = detail.json()
            current_dns = d.get("current_dns", {})
            result["current_dns"] = {
                rtype: [r.get("address") or r.get("host") or r.get("value", "")
                        for r in vals.get("values", [])]
                for rtype, vals in current_dns.items()
                if isinstance(vals, dict) and "values" in vals
            }
            result["alexa_rank"] = d.get("alexa_rank")
            result["hostname"] = d.get("hostname")
        except Exception:
            log.warning("SecurityTrails domain detail failed for %r", domain)

        try:
            subs = self._http.get(
                f"{base}/domain/{domain}/subdomains",
                headers=headers, timeout=12,
            )
            subs.raise_for_status()
            sub_list = subs.json().get("subdomains", [])
            result["subdomains"] = [f"{s}.{domain}" for s in sub_list[:100]]
            result["subdomain_count"] = len(sub_list)
        except Exception:
            log.warning("SecurityTrails subdomains failed for %r", domain)

        try:
            assoc = self._http.get(
                f"{base}/domain/{domain}/associated",
                headers=headers, timeout=12,
            )
            assoc.raise_for_status()
            records = assoc.json().get("records", [])
            result["associated_domains"] = [
                r.get("hostname", "") for r in records[:50]
            ]
        except Exception:
            log.warning("SecurityTrails associated domains failed for %r", domain)

        try:
            history = self._http.get(
                f"{base}/domain/{domain}/history/dns/a",
                headers=headers, timeout=12,
            )
            history.raise_for_status()
            records = history.json().get("records", [])
            result["dns_history_a"] = [
                {
                    "values": [v.get("ip", "") for v in r.get("values", [])],
                    "first_seen": r.get("first_seen", ""),
                    "last_seen": r.get("last_seen", ""),
                    "organizations": r.get("organizations", []),
                }
                for r in records[:20]
            ]
        except Exception:
            log.warning("SecurityTrails DNS history failed for %r", domain)

        if any(k in result for k in ("current_dns", "subdomains", "associated_domains", "dns_history_a")):
            log.info("SecurityTrails for %s: %d subdomains, %d associated",
                     domain, result.get("subdomain_count", 0),
                     len(result.get("associated_domains", [])))

        return result if len(result) > 1 else {}

    def securitytrails_ip(self, ip: str) -> dict[str, Any]:
        """Reverse lookup: domains hosted on an IP via SecurityTrails."""
        api_key = os.environ.get("SECURITYTRAILS_API_KEY")
        if not api_key:
            return {}

        try:
            resp = self._http.get(
                f"https://api.securitytrails.com/v1/domains/list",
                headers={"APIKEY": api_key, "Accept": "application/json"},
                params={"include_ips": "false", "page": 1},
                json={"filter": {"ipv4": ip}},
                timeout=12,
            )
            resp.raise_for_status()
            data = resp.json()
            records = data.get("records", [])
            return {
                "ip": ip,
                "domains": [r.get("hostname", "") for r in records[:50]],
                "domain_count": data.get("record_count", len(records)),
            }
        except Exception:
            log.warning("SecurityTrails IP reverse failed for %r", ip)
            return {}

    # ── URLScan.io ────────────────────────────────────────────────

    def urlscan_search(self, query: str, query_type: str = "domain") -> dict[str, Any]:
        """Search URLScan.io for scans of a domain/IP/URL.

        Requires URLSCAN_API_KEY for submission; search is free without key.
        Free tier: 100 scans/day, unlimited search.
        """
        api_key = os.environ.get("URLSCAN_API_KEY", "")
        headers = {"Accept": "application/json"}
        if api_key:
            headers["API-Key"] = api_key

        try:
            search_query = f"{query_type}:{query}" if query_type in ("domain", "ip") else f"page.url:{query}"
            resp = self._http.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": search_query, "size": 10},
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])

            scans = []
            for r in results[:10]:
                task = r.get("task", {})
                page = r.get("page", {})
                stats = r.get("stats", {})
                scans.append({
                    "url": task.get("url", ""),
                    "domain": page.get("domain", ""),
                    "ip": page.get("ip", ""),
                    "country": page.get("country", ""),
                    "server": page.get("server", ""),
                    "status": page.get("status"),
                    "title": page.get("title", ""),
                    "asn": page.get("asn", ""),
                    "asnname": page.get("asnname", ""),
                    "screenshot": r.get("screenshot", ""),
                    "result_url": r.get("result", ""),
                    "time": task.get("time", ""),
                    "malicious": r.get("verdicts", {}).get("overall", {}).get("malicious", False),
                    "tags": r.get("verdicts", {}).get("overall", {}).get("tags", []),
                    "unique_ips": stats.get("uniqIPs", 0),
                })

            log.info("URLScan.io search for %s:%s returned %d results",
                     query_type, query, len(scans))

            return {
                "query": query,
                "query_type": query_type,
                "total": data.get("total", len(scans)),
                "scans": scans,
            }
        except Exception:
            log.warning("URLScan.io search failed for %r", query)
            return {}

    def urlscan_submit(self, url: str, visibility: str = "unlisted") -> dict[str, Any]:
        """Submit a URL to URLScan.io for scanning.

        Requires URLSCAN_API_KEY. Free tier: 100 scans/day.
        """
        api_key = os.environ.get("URLSCAN_API_KEY")
        if not api_key:
            return {}

        try:
            resp = self._http.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": api_key, "Content-Type": "application/json"},
                json={"url": url, "visibility": visibility},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "uuid": data.get("uuid", ""),
                "result_url": data.get("result", ""),
                "api_url": data.get("api", ""),
                "visibility": data.get("visibility", visibility),
                "message": data.get("message", ""),
            }
        except Exception:
            log.warning("URLScan.io submit failed for %r", url)
            return {}

    # ── FullContact ───────────────────────────────────────────────

    def fullcontact_enrich(self, email: str = "", domain: str = "") -> dict[str, Any]:
        """Enrich a person (by email) or company (by domain) via FullContact.

        Requires FULLCONTACT_API_KEY. Free tier: 100 matches/month.
        """
        api_key = os.environ.get("FULLCONTACT_API_KEY")
        if not api_key:
            return {}

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        result: dict[str, Any] = {}

        if email:
            try:
                resp = self._http.post(
                    "https://api.fullcontact.com/v3/person.enrich",
                    headers=headers,
                    json={"email": email},
                    timeout=12,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result["person"] = {
                        "full_name": data.get("fullName", ""),
                        "age_range": data.get("ageRange", ""),
                        "gender": data.get("gender", ""),
                        "location": data.get("location", ""),
                        "title": data.get("title", ""),
                        "organization": data.get("organization", ""),
                        "linkedin": data.get("linkedin", ""),
                        "twitter": data.get("twitter", ""),
                        "facebook": data.get("facebook", ""),
                        "bio": data.get("bio", ""),
                        "avatar": data.get("avatar", ""),
                        "details": {
                            "interests": data.get("details", {}).get("interests", []),
                            "locations": [
                                loc.get("formatted", "")
                                for loc in data.get("details", {}).get("locations", [])
                            ],
                        },
                    }
                    log.info("FullContact person enrich for %s: %s",
                             email, result["person"].get("full_name", "unknown"))
                elif resp.status_code == 404:
                    log.info("FullContact: no person record for %s", email)
                else:
                    log.warning("FullContact person enrich returned %d for %s",
                                resp.status_code, email)
            except Exception:
                log.warning("FullContact person enrich failed for %r", email)

        if domain:
            try:
                resp = self._http.post(
                    "https://api.fullcontact.com/v3/company.enrich",
                    headers=headers,
                    json={"domain": domain},
                    timeout=12,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result["company"] = {
                        "name": data.get("name", ""),
                        "location": data.get("location", ""),
                        "category": data.get("category", []),
                        "logo": data.get("logo", ""),
                        "website": data.get("website", ""),
                        "founded": data.get("founded"),
                        "employees": data.get("employees"),
                        "locale": data.get("locale", ""),
                        "linkedin": data.get("linkedin", ""),
                        "twitter": data.get("twitter", ""),
                        "facebook": data.get("facebook", ""),
                        "bio": data.get("bio", ""),
                        "keywords": data.get("details", {}).get("keywords", []),
                    }
                    log.info("FullContact company enrich for %s: %s",
                             domain, result["company"].get("name", "unknown"))
                elif resp.status_code == 404:
                    log.info("FullContact: no company record for %s", domain)
                else:
                    log.warning("FullContact company enrich returned %d for %s",
                                resp.status_code, domain)
            except Exception:
                log.warning("FullContact company enrich failed for %r", domain)

        return result

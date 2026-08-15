"""Web scraping and lookup utilities for Fortis Intelligence Hub."""

import logging
import os
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import feedparser
import requests
import whois
from newsapi import NewsApiClient

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

    def fetch_news(
        self,
        query: str,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self._newsapi:
            log.warning("NewsAPI not configured — set NEWSAPI_KEY environment variable")
            return []
        try:
            params: dict[str, Any] = {"q": query, "language": "en", "sort_by": "relevancy"}
            if date_from:
                params["from_param"] = date_from
            if date_to:
                params["to"] = date_to
            response = self._newsapi.get_everything(**params)
            articles: list[dict[str, Any]] = []
            for article in response.get("articles", []):
                source = article.get("source") or {}
                articles.append({
                    "title": article.get("title", ""),
                    "url": article.get("url", ""),
                    "source": source.get("name", ""),
                    "published": article.get("publishedAt", ""),
                    "snippet": article.get("description", ""),
                })
            return articles
        except Exception:
            log.exception("Unexpected error fetching news for query=%r", query)
            return []

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
        record_types = ["A", "AAAA", "MX", "TXT", "NS"]
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
            resp = requests.get(robots_url, timeout=10)
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
                resp = requests.get(f"{base}/domains/{indicator}", headers=headers, timeout=15)
            elif indicator_type == "ip":
                resp = requests.get(f"{base}/ip_addresses/{indicator}", headers=headers, timeout=15)
            elif indicator_type == "hash":
                resp = requests.get(f"{base}/files/{indicator}", headers=headers, timeout=15)
            elif indicator_type == "url":
                # URL analysis requires a POST first, then a GET on the analysis
                submit_resp = requests.post(
                    f"{base}/urls",
                    headers=headers,
                    data={"url": indicator},
                    timeout=15,
                )
                submit_resp.raise_for_status()
                analysis_id = submit_resp.json()["data"]["id"]
                resp = requests.get(
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

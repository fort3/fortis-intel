"""Fortis Intelligence Hub -- Flask application factory.

OSINT analysis platform with ForgeChain governance, FAISS knowledge base,
and multi-source intelligence aggregation.
"""

import base64
import hashlib
import hmac as hmac_mod
import json as _json
import os
import re
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Windows UTF-8 encoding fix
if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

from dotenv import load_dotenv
from flask import (
    Flask, jsonify, make_response, render_template,
    request, session, g, redirect, url_for,
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── App imports ────────────────────────────────────────────────────
from app.auth import (
    login_required,
    admin_required,
    get_oauth_client,
    OAuthError,
    session_manager,
    get_audit_logger,
    validate_auth_config,
    ADMIN_EMAILS,
)
from app.auth.config import AUTH_ENABLED, SESSION_SECRET_KEY, SESSION_TIMEOUT_MINUTES
from app.chains import (
    get_rag_chain,
    get_investigation_chain,
    get_enrichment_chain,
    get_geolocation_chain,
    get_batch_item_chain,
    get_batch_synthesis_chain,
    get_scenario_chain,
)
from app.rag_store import (
    build_vectorstore,
    load_vectorstore,
    add_to_knowledge_base,
    query_knowledge_base,
    knowledge_base_exists,
    rebuild_knowledge_base,
    verify_kb_on_startup,
)
from app.report_store import AnalysisReport, get_report_store
from app.export import generate_pdf, generate_markdown
from app.export_ioc import convert_to_stix21, convert_to_csv, convert_to_json
from app.charts import generate_investigation_charts
from app.intel_graph import (
    build_investigation_graph,
    graph_to_cytoscape_json,
    graph_context,
    cache_graph,
    persist_relationships,
    query_shared_connections,
    query_location_clusters,
    query_activity_overlap,
)
from app.forge import gated_invoke
from app.forge.config import FORGE_ENABLED
from app.forge.chain_store import get_chain_store
from app.forge.replay import get_session_replay
from app.osint_client import OSINTClient
from app.geo_client import GeoClient
from app.feed_monitor import FeedMonitor
from app.gdrive_client import get_gdrive_client
from app.utils import create_session_id, safe_storage_path, validate_session_id
from app.utils.pdf_reader import extract_pdf_text
from app.utils.uploads import validate_upload_file
from app.utils.sanitizer import sanitize_identifier
from app.constants import (
    SOCIAL_PLATFORMS,
    SENSITIVITY_LEVELS,
    IDENTIFIER_TYPES,
    INVESTIGATION_DEPTHS,
    SCENARIO_TYPES,
)

# ── Constants ──────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR / "data"
VECTORSTORE_DIR = BASE_DIR / "vectorstores"
LOG_DIR = BASE_DIR / "logs"

stored_reports: dict = {}
_MAX_STORED_REPORTS = 500
_KB_CONTEXT_MAX_CHARS = 2000

# ── Helper functions ───────────────────────────────────────────────


def _get_user_hash() -> str:
    """SHA-256 hash prefix of the current user's email for audit logs."""
    if hasattr(g, "user_session"):
        return hashlib.sha256(g.user_session.email.encode()).hexdigest()[:16]
    return "unknown"


def _is_admin() -> bool:
    """Check if the current request user is an admin."""
    return getattr(getattr(g, "user_session", None), "is_admin", False)



def _save_to_kb(
    source_route: str,
    report_type: str,
    analysis_text: str,
    subject_identifier: str | None = None,
    identifier_type: str | None = None,
    sensitivity_level: str = "INTERNAL",
    platforms_queried: list[str] | None = None,
    entity_count: int = 0,
    source_count: int = 0,
    tags: list[str] | None = None,
) -> str | None:
    """Save a report to the ReportStore and index it in the FAISS knowledge base."""
    try:
        report_id = uuid.uuid4().hex
        user_hash = _get_user_hash()

        chunk_count = 0
        try:
            chunk_count = add_to_knowledge_base(analysis_text, report_id)
        except Exception as exc:
            print(f"[WARN] KB vectorstore update failed (non-fatal): {exc}")

        report = AnalysisReport(
            report_id=report_id,
            source_route=source_route,
            report_type=report_type,
            analysis_text=analysis_text,
            subject_identifier=subject_identifier,
            identifier_type=identifier_type,
            sensitivity_level=sensitivity_level,
            platforms_queried=_json.dumps(platforms_queried) if platforms_queried else None,
            entity_count=entity_count,
            source_count=source_count,
            created_at=datetime.now(tz=timezone.utc).isoformat(),
            created_by=user_hash,
            in_knowledge_base=chunk_count > 0,
            kb_chunk_count=chunk_count,
            tags=_json.dumps(tags) if tags else None,
        )
        get_report_store().save(report)
        subject_short = (subject_identifier or "")[:50]
        print(f"[KB] Saved report {report_id[:8]} ({report_type}: {subject_short}) -- {chunk_count} chunks")
        return report_id
    except Exception as exc:
        print(f"[ERROR] _save_to_kb failed (non-fatal): {exc}")
        return None


def _get_kb_context(query: str) -> str:
    """Query the global FAISS knowledge base for supplemental context."""
    try:
        chunks = query_knowledge_base(query, k=3)
        if not chunks:
            return ""
        kb_text = "\n\n".join(chunks)
        if len(kb_text) > _KB_CONTEXT_MAX_CHARS:
            kb_text = kb_text[:_KB_CONTEXT_MAX_CHARS] + "..."
        return f"\n\n=== Prior Intelligence (Knowledge Base) ===\n{kb_text}"
    except Exception as exc:
        print(f"[WARN] KB query failed (non-fatal): {exc}")
        return ""


def _rebuild_kb_from_store() -> int:
    """Rebuild the FAISS knowledge base from all in-KB reports."""
    try:
        store = get_report_store()
        reports = store.get_all_in_kb()
        texts = [(r.report_id, r.analysis_text) for r in reports]
        count = rebuild_knowledge_base(texts)
        print(f"[KB] Rebuilt with {count} chunks from {len(texts)} reports")
        return count
    except Exception as exc:
        print(f"[ERROR] KB rebuild failed: {exc}")
        return 0


def _findings_to_context(findings_dict: dict) -> str:
    """Convert serialized OSINTFindings to a text context for chain input."""
    parts: list[str] = []

    profiles = findings_dict.get("profiles", [])
    if profiles:
        parts.append(f"=== Social Profiles ({len(profiles)}) ===")
        for p in profiles[:20]:
            line = f"  [{p.get('platform', '?')}] @{p.get('username', '?')} - {p.get('display_name', '')}"
            parts.append(line)
            bio = p.get("bio", "")
            if bio:
                parts.append(f"    Bio: {bio[:200]}")
            followers = p.get("followers")
            if followers:
                parts.append(f"    Followers: {followers}")

    posts = findings_dict.get("posts", [])
    if posts:
        parts.append(f"\n=== Recent Posts ({len(posts)}) ===")
        for post in posts[:15]:
            ts = post.get("timestamp", "")
            content = post.get("content", "")[:200]
            parts.append(f"  [{post.get('platform', '?')}] {ts}: {content}")

    web_mentions = findings_dict.get("web_mentions", [])
    if web_mentions:
        parts.append(f"\n=== Web Mentions ({len(web_mentions)}) ===")
        for wm in web_mentions[:10]:
            parts.append(
                f"  [{wm.get('domain', '?')}] {wm.get('source_title', '')}: "
                f"{wm.get('snippet', '')[:200]}"
            )

    geo_points = findings_dict.get("geo_points", [])
    if geo_points:
        parts.append(f"\n=== Geo Points ({len(geo_points)}) ===")
        for gp in geo_points[:10]:
            conf = gp.get("confidence", 0)
            conf_str = f"{conf:.0%}" if isinstance(conf, float) else str(conf)
            parts.append(
                f"  ({gp.get('lat', '?')}, {gp.get('lon', '?')}) "
                f"- {gp.get('source', '')} [{conf_str}]"
            )

    entities = findings_dict.get("entities", [])
    if entities:
        parts.append(f"\n=== Extracted Entities ({len(entities)}) ===")
        for e in entities[:20]:
            conf = e.get("confidence", 0)
            conf_str = f"{conf:.0%}" if isinstance(conf, float) else str(conf)
            parts.append(f"  [{e.get('entity_type', '?')}] {e.get('entity_value', '?')} (confidence: {conf_str})")

    timeline = findings_dict.get("timeline", [])
    if timeline:
        parts.append(f"\n=== Timeline Events ({len(timeline)}) ===")
        for evt in timeline[:10]:
            parts.append(f"  {evt}")

    errors = findings_dict.get("errors", [])
    if errors:
        parts.append(f"\n=== Collection Errors ({len(errors)}) ===")
        for err in errors:
            parts.append(f"  - {err}")

    if not parts:
        return "No OSINT data collected. OSINT sources are in Phase 0 (stub mode)."

    return "\n".join(parts)


def _geo_points_to_text(geo_points: list[dict]) -> str:
    """Convert geo data points to text context for chain input."""
    if not geo_points:
        return "No geolocation data available."
    parts = []
    for gp in geo_points[:20]:
        conf = gp.get("confidence", 0)
        conf_str = f"{conf:.0%}" if isinstance(conf, float) else str(conf)
        parts.append(
            f"- ({gp.get('lat', '?')}, {gp.get('lon', '?')}) "
            f"source={gp.get('source', '?')} confidence={conf_str} "
            f"type={gp.get('point_type', '?')} ts={gp.get('timestamp', '?')}"
        )
    return "\n".join(parts)


def _process_single_identifier(identifier, identifier_type, platforms, depth,
                               osint_client, geo_client, session_id, user_hash,
                               elevated=False):
    """Process a single identifier for batch investigation."""
    try:
        clean_id = sanitize_identifier(identifier, identifier_type)
    except Exception:
        clean_id = identifier

    try:
        findings = osint_client.investigate(clean_id, platforms=platforms, depth=depth)
        findings_dict = asdict(findings)
    except Exception as exc:
        return {
            "success": False,
            "identifier": identifier,
            "identifier_type": identifier_type,
            "error": f"OSINT collection failed: {str(exc)[:200]}",
        }

    osint_context = _findings_to_context(findings_dict)
    geo_context = _geo_points_to_text(findings_dict.get("geo_points", []))

    chain = get_batch_item_chain()
    chain_input = {
        "osint_data": osint_context,
        "geo_data": geo_context,
        "subject_identifier": clean_id,
        "identifier_type": identifier_type,
        "elevated_authorization": elevated,
    }

    analysis = ""
    try:
        result = gated_invoke(
            chain=chain,
            chain_input=chain_input,
            chain_name="batch_item_chain",
            endpoint="/batch-investigate",
            session_id=session_id or f"batch_{clean_id}",
            mode="osint",
            user_hash=user_hash,
            trusted_keys={"osint_data", "geo_data"},
        )
        if result.success:
            analysis = result.content
        else:
            analysis = f"[Governance blocked: {result.reason}]"
    except Exception as exc:
        analysis = f"[LLM analysis failed: {str(exc)[:150]}]"

    return {
        "success": True,
        "identifier": clean_id,
        "identifier_type": identifier_type,
        "analysis": analysis,
        "entity_count": len(findings_dict.get("entities", [])),
        "source_count": len(findings_dict.get("platforms_queried", [])),
        "sensitivity_level": findings_dict.get("sensitivity_level", "INTERNAL"),
        "error": None,
    }


# ── Application factory ───────────────────────────────────────────


def create_app():
    load_dotenv()

    # Validate auth config if authentication is enabled
    if AUTH_ENABLED:
        try:
            validate_auth_config()
        except ValueError as exc:
            print(f"[ERROR] Authentication configuration invalid: {exc}")

    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    # ── Session configuration ──────────────────────────────────────
    app.config.update(
        SECRET_KEY=SESSION_SECRET_KEY,
        MAX_CONTENT_LENGTH=50 * 1024 * 1024,  # 50 MB upload limit
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="__Host-fortis-session",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_TIMEOUT_MINUTES),
    )

    # ── CORS ───────────────────────────────────────────────────────
    allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5000").split(",")
    CORS(
        app,
        origins=allowed_origins,
        supports_credentials=True,
        max_age=3600,
    )

    # ── Rate limiting ──────────────────────────────────────────────
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["1000 per day", "200 per hour"],
        storage_uri=os.getenv("REDIS_URL", "memory://"),
    )

    # ── Security headers ───────────────────────────────────────────
    @app.after_request
    def set_security_headers(response):
        """Apply security headers to every response."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        if os.getenv("FLASK_ENV") == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
            "https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://*.basemaps.cartocdn.com "
            "https://*.tile.openstreetmap.org https://server.arcgisonline.com; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "base-uri 'self'"
        )

        return response

    # ── Initialize directories ─────────────────────────────────────
    for directory in (UPLOAD_DIR, DATA_DIR, VECTORSTORE_DIR, LOG_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    # ── Initialize databases ───────────────────────────────────────
    try:
        get_report_store()
        print("[STARTUP] ReportStore initialized")
    except Exception as exc:
        print(f"[ERROR] ReportStore init failed: {exc}")

    try:
        get_chain_store()
        print("[STARTUP] ForgeChain store initialized")
    except Exception as exc:
        print(f"[ERROR] ForgeChain store init failed: {exc}")

    # ================================================================
    #  AUTH ROUTES
    # ================================================================

    @app.route("/")
    def welcome():
        """Serve welcome page. Redirect to app if already authenticated."""
        auth_on = os.getenv("AUTH_ENABLED", "true").lower() == "true"
        if auth_on:
            token = session.get("auth_token")
            if token and session_manager.get_session(token):
                return redirect(url_for("app_page"))
        return render_template("welcome.html", auth_enabled=auth_on)

    @app.route("/oauth/login", methods=["GET"])
    def oauth_login():
        """Initiate Google OAuth flow."""
        try:
            oauth_client = get_oauth_client()
            authorization_url, state = oauth_client.get_authorization_url()

            session["oauth_state"] = state
            session.permanent = True

            return redirect(authorization_url)
        except Exception as exc:
            print(f"[ERROR] OAuth initialization failed: {exc}")
            return redirect(url_for("welcome", error="oauth_init_failed"))

    @app.route("/oauth/callback", methods=["GET"])
    @limiter.limit("10 per minute")
    def oauth_callback():
        """Handle OAuth callback from Google."""
        audit_logger = get_audit_logger()

        error = request.args.get("error")
        if error:
            print(f"[ERROR] OAuth error: {error}")
            return redirect(url_for("welcome", error="oauth_denied"))

        code = request.args.get("code")
        state = request.args.get("state")

        # Verify state token (CSRF protection)
        stored_state = session.get("oauth_state")
        if not state or not stored_state or not hmac_mod.compare_digest(state, stored_state):
            print("[ERROR] OAuth state mismatch (CSRF attempt)")
            audit_logger._log_event("CSRF_ATTEMPT", {"state": state})
            session.pop("oauth_state", None)
            return redirect(url_for("welcome", error="csrf_detected"))

        try:
            oauth_client = get_oauth_client()
            user_info = oauth_client.exchange_code_for_token(code, state)
            email = user_info["email"]

            # Log successful login
            audit_logger.log_login_success(email)

            # Create session
            session_token = session_manager.create_session(
                email=email,
                name=user_info.get("name", email),
                picture=user_info.get("picture", ""),
            )

            # Set session cookie
            session["auth_token"] = session_token
            session["user_name"] = user_info.get("name", email)
            session["user_picture"] = user_info.get("picture", "")
            session.permanent = True

            # Clear OAuth state
            session.pop("oauth_state", None)

            return redirect(url_for("app_page"))

        except OAuthError as exc:
            audit_logger.log_login_attempt("unknown", False, f"OAuth error: {str(exc)}")
            print(f"[ERROR] OAuth exchange failed: {exc}")
            return redirect(url_for("welcome", error="oauth_failed"))
        except Exception as exc:
            email_local = email if "email" in dir() else "unknown"
            audit_logger.log_login_attempt(email_local, False, f"Server error: {str(exc)}")
            print(f"[ERROR] Login failed: {exc}")
            return redirect(url_for("welcome", error="server_error"))

    @app.route("/app")
    @login_required
    def app_page():
        """Serve the main SPA."""
        return render_template("index.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        """Destroy the current session."""
        audit_logger = get_audit_logger()
        audit_logger.log_logout(g.user_session.email)

        token = session.get("auth_token")
        if token:
            session_manager.invalidate_session(token)
        session.clear()
        return jsonify({"success": True})

    @app.route("/me", methods=["GET"])
    @login_required
    def get_current_user():
        """Return current user info."""
        user_session = g.user_session
        return jsonify({
            "email": user_session.email,
            "name": session.get("user_name", user_session.email),
            "picture": session.get("user_picture", ""),
            "is_admin": user_session.is_admin,
        })

    # ================================================================
    #  CORE ANALYSIS ROUTES
    # ================================================================

    @app.route("/upload", methods=["POST"])
    @login_required
    @limiter.limit("20 per hour")
    def upload():
        """Upload a PDF or Markdown file, extract text, and build vectorstore."""
        try:
            file = request.files.get("file") or request.files.get("pdf")
            if not file or not file.filename:
                return jsonify({"error": "No file uploaded"}), 400

            # Validate file type and size
            is_valid, error_msg = validate_upload_file(file)
            if not is_valid:
                print(f"  File validation failed: {error_msg}")
                return jsonify({"error": error_msg}), 400

            ext = Path(file.filename).suffix.lower()
            try:
                session_id = create_session_id(file.filename)
                path = safe_storage_path(str(UPLOAD_DIR), session_id, suffix=ext)
            except ValueError as ve:
                return jsonify({"error": f"Invalid session ID: {ve}"}), 400

            file.save(path)

            print(f"\nDocument Upload ({ext}):")
            print(f"  Original filename: {file.filename}")
            print(f"  Session ID: {session_id}")

            if ext == ".md":
                text = path.read_text(encoding="utf-8")
            else:
                text = extract_pdf_text(str(path))

            if not text or len(text.strip()) < 50:
                error_msg = (
                    f"Document appears to be empty or unreadable. "
                    f"Extracted {len(text)} characters."
                )
                print(f"  Error: {error_msg}")
                return jsonify({"error": error_msg}), 400

            # Enforce in-memory report cache limit
            if len(stored_reports) >= _MAX_STORED_REPORTS:
                oldest_key = min(
                    stored_reports,
                    key=lambda k: stored_reports[k].get("created_at", datetime.min),
                )
                stored_reports.pop(oldest_key, None)

            stored_reports[session_id] = {
                "text": text,
                "user_email": g.user_session.email if hasattr(g, "user_session") else "unknown",
                "created_at": datetime.now(tz=timezone.utc),
            }

            # Build vectorstore for RAG queries
            try:
                build_vectorstore(text, session_id)
            except Exception as exc:
                print(f"  Warning: Could not build vectorstore: {exc}")

            # Save to KB so it appears in the Knowledge Base panel
            report_id = _save_to_kb(
                source_route="/upload",
                report_type="ingestion",
                analysis_text=text,
                subject_identifier=file.filename,
                sensitivity_level="INTERNAL",
            )

            # MITRE technique extraction
            mitre_techniques = []
            try:
                from app.mitre import extract_mitre_techniques
                mitre_techniques = extract_mitre_techniques(text[:10000])
            except Exception:
                pass

            pages = None
            chunks = None
            try:
                vs_path = os.path.join(str(VECTORSTORE_DIR), session_id)
                if os.path.isdir(vs_path):
                    import glob as _glob
                    chunk_files = _glob.glob(os.path.join(vs_path, "*.pkl"))
                    if chunk_files:
                        chunks = len(chunk_files)
            except Exception:
                pass

            return jsonify({
                "session_id": session_id,
                "message": "Document ingested successfully",
                "char_count": len(text),
                "report_id": report_id,
                "mitre_techniques": mitre_techniques,
                "pages": pages,
                "chunks": chunks,
            })

        except Exception as exc:
            print(f"Error during document upload: {exc}")
            return jsonify({"error": "Failed to process document. Please try again."}), 500

    @app.route("/ask", methods=["POST"])
    @login_required
    @limiter.limit("60 per hour")
    def ask():
        """RAG question-answering over uploaded documents and knowledge base."""
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id")
        question = data.get("question")

        if not question:
            return jsonify({"error": "Question is required"}), 400

        # Build context from vectorstore and/or KB
        context = ""
        kb_context = ""

        if session_id and validate_session_id(session_id) and session_id in stored_reports:
            try:
                vs = load_vectorstore(session_id)
                docs = vs.similarity_search(question, k=5)
                context = "\n\n".join(doc.page_content for doc in docs)
            except Exception:
                context = stored_reports[session_id]["text"]
            kb_context = _get_kb_context(question)
        else:
            kb_context = _get_kb_context(question)
            if not kb_context:
                return jsonify({
                    "error": "No context available. Upload a document or run an investigation first."
                }), 400
            session_id = session_id or f"kb_{uuid.uuid4().hex[:16]}"

        chain = get_rag_chain()
        chain_input = {
            "context": context,
            "kb_context": kb_context,
            "question": question,
        }

        user_hash = _get_user_hash()
        result = gated_invoke(
            chain,
            chain_input,
            chain_name="rag_chain",
            endpoint="/ask",
            mode="osint",
            session_id=session_id,
            user_hash=user_hash,
            trusted_keys={"context", "kb_context"},
        )

        if not result.success:
            return jsonify({
                "error": "Request blocked by governance",
                "reason": result.reason,
                "block_id": result.block_id,
                "gate_outcome": result.gate_outcome,
            }), 403

        answer = result.content

        _save_to_kb(
            source_route="/ask",
            report_type="qa_answer",
            analysis_text=f"Q: {question}\n\nA: {answer}",
            subject_identifier=question[:100],
            sensitivity_level="INTERNAL",
        )

        # Append Q&A to stored_reports so export can find it
        if session_id and session_id in stored_reports:
            prev = stored_reports[session_id].get("text", "")
            stored_reports[session_id]["text"] = (
                prev + f"\n\nQ: {question}\n\nA: {answer}"
            ).strip()
        elif session_id:
            stored_reports[session_id] = {
                "text": f"Q: {question}\n\nA: {answer}",
                "user_email": g.user_session.email if hasattr(g, "user_session") else "unknown",
                "created_at": datetime.now(tz=timezone.utc),
            }

        return jsonify({
            "answer": answer,
            "session_id": session_id,
        })

    # ================================================================
    #  OSINT INVESTIGATION ROUTES (Phase 0)
    # ================================================================

    @app.route("/investigate", methods=["POST"])
    @login_required
    @limiter.limit("20 per hour")
    def investigate():
        """Full OSINT investigation for a subject identifier."""
        data = request.get_json(silent=True) or {}
        identifier = data.get("identifier", "").strip()
        identifier_type = data.get("identifier_type", "").strip().lower()
        platforms = data.get("platforms", list(SOCIAL_PLATFORMS.keys()))
        depth = data.get("depth", "standard").strip().lower()
        investigation_purpose = data.get("investigation_purpose", "").strip()

        # Input validation
        if not identifier:
            return jsonify({"error": "Identifier is required"}), 400
        if identifier_type not in IDENTIFIER_TYPES:
            return jsonify({
                "error": f"Invalid identifier_type. Must be one of: {', '.join(IDENTIFIER_TYPES)}"
            }), 400
        if depth not in INVESTIGATION_DEPTHS:
            return jsonify({
                "error": f"Invalid depth. Must be one of: {', '.join(INVESTIGATION_DEPTHS.keys())}"
            }), 400

        # Validate and filter platforms
        if isinstance(platforms, list):
            platforms = [p for p in platforms if p in SOCIAL_PLATFORMS]
        if not platforms:
            platforms = list(SOCIAL_PLATFORMS.keys())

        # Sanitize identifier
        try:
            clean_id = sanitize_identifier(identifier, identifier_type)
        except Exception:
            clean_id = identifier

        session_id = f"inv_{uuid.uuid4().hex[:16]}"
        user_hash = _get_user_hash()

        # Phase 0: OSINT collection (stubs will return minimal data)
        osint_client = OSINTClient()
        geo_client = GeoClient()

        try:
            findings = osint_client.investigate(clean_id, platforms=platforms, depth=depth)
            findings_dict = asdict(findings)
        except Exception as exc:
            print(f"[ERROR] OSINT investigation failed: {exc}")
            return jsonify({"error": "OSINT collection failed. Please try again."}), 500

        # Build context for chain
        osint_context = _findings_to_context(findings_dict)
        geo_data = findings_dict.get("geo_points", [])
        geo_context = _geo_points_to_text(geo_data)
        kb_context = _get_kb_context(f"{identifier_type} {clean_id} investigation")

        # Build entity graph
        entities_data = findings_dict.get("entities", [])
        try:
            entity_graph = build_investigation_graph(entities_data)
            graph_json = graph_to_cytoscape_json(entity_graph)
            entity_graph_ctx = graph_context(entity_graph, max_chars=4000)
            graph_cache_key = cache_graph(entity_graph, session_id)
        except Exception as exc:
            print(f"[WARN] Graph construction failed (non-fatal): {exc}")
            entity_graph = None
            graph_json = {"nodes": [], "edges": []}
            entity_graph_ctx = "No entity graph available."
            graph_cache_key = ""

        # Persist entity relationships to SQLite for cross-investigation queries
        try:
            if entity_graph and entity_graph.number_of_edges() > 0:
                persisted = persist_relationships(entity_graph, get_report_store())
                print(f"[GRAPH] Persisted {persisted} relationships for {clean_id}")
        except Exception as exc:
            print(f"[WARN] Relationship persistence failed (non-fatal): {exc}")

        # Build map data in the shape the frontend renderMap() expects
        map_data = {}
        try:
            if geo_data:
                markers = []
                for gp in geo_data:
                    lat = gp.get("lat")
                    lon = gp.get("lon") or gp.get("lng")
                    if lat is None or lon is None:
                        continue
                    markers.append({
                        "lat": float(lat),
                        "lng": float(lon),
                        "label": gp.get("label") or gp.get("name", ""),
                        "source_type": gp.get("source", "osint"),
                        "confidence": gp.get("confidence", 0.5),
                    })
                if markers:
                    lats = [m["lat"] for m in markers]
                    lngs = [m["lng"] for m in markers]
                    map_data = {
                        "markers": markers,
                        "center": [sum(lats) / len(lats), sum(lngs) / len(lngs)],
                        "zoom": GeoClient._auto_zoom(
                            [min(lats), min(lngs)],
                            [max(lats), max(lngs)],
                        ) if len(markers) > 1 else 10,
                    }
        except Exception as exc:
            print(f"[WARN] Map data construction failed (non-fatal): {exc}")

        # Generate charts
        charts = {}
        try:
            all_findings = (
                findings_dict.get("profiles", [])
                + findings_dict.get("posts", [])
                + findings_dict.get("web_mentions", [])
            )
            charts = generate_investigation_charts(all_findings, entities_data)
        except Exception as exc:
            print(f"[WARN] Chart generation failed (non-fatal): {exc}")

        # Chain invocation via ForgeChain governance
        chain = get_investigation_chain()
        chain_input = {
            "osint_data": osint_context,
            "geo_data": geo_context,
            "entity_graph_context": entity_graph_ctx,
            "subject_identifier": clean_id,
            "identifier_type": identifier_type,
            "kb_context": kb_context,
            "elevated_authorization": _is_admin(),
        }

        result = gated_invoke(
            chain,
            chain_input,
            chain_name="investigation_chain",
            endpoint="/investigate",
            mode="osint",
            session_id=session_id,
            user_hash=user_hash,
            trusted_keys={"osint_data", "geo_data", "entity_graph_context", "kb_context"},
        )

        if not result.success:
            return jsonify({
                "error": "Request blocked by governance",
                "reason": result.reason,
                "block_id": result.block_id,
                "gate_outcome": result.gate_outcome,
            }), 403

        analysis = result.content
        sensitivity = findings_dict.get("sensitivity_level", "INTERNAL")

        # Save to knowledge base
        report_id = _save_to_kb(
            source_route="/investigate",
            report_type="investigation",
            analysis_text=analysis,
            subject_identifier=clean_id,
            identifier_type=identifier_type,
            sensitivity_level=sensitivity,
            platforms_queried=findings_dict.get("platforms_queried", platforms),
            entity_count=len(entities_data),
            source_count=len(findings_dict.get("platforms_queried", [])),
        )

        # Cache in-memory for follow-up queries and export
        stored_reports[session_id] = {
            "text": analysis,
            "entities": entities_data,
            "sensitivity_level": sensitivity,
            "identifier": clean_id,
            "chart_data": charts,
            "user_email": g.user_session.email if hasattr(g, "user_session") else "unknown",
            "created_at": datetime.now(tz=timezone.utc),
        }

        response = {
            "report_id": report_id,
            "session_id": session_id,
            "analysis": analysis,
            "map_data": map_data,
            "entity_graph": graph_json,
            "charts": charts,
            "sensitivity_level": sensitivity,
            "identifier": clean_id,
            "identifier_type": identifier_type,
            "entities": entities_data,
            "entity_count": len(entities_data),
            "source_count": len(findings_dict.get("platforms_queried", [])),
        }
        if graph_cache_key:
            response["graph_cache_key"] = graph_cache_key

        return jsonify(response)

    @app.route("/enrich", methods=["POST"])
    @login_required
    @limiter.limit("15 per hour")
    def enrich():
        """Enrich an existing document with OSINT data."""
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id")
        identifier = data.get("identifier", "").strip()
        identifier_type = data.get("identifier_type", "username").strip().lower()
        investigation_purpose = data.get("investigation_purpose", "").strip()

        # Need either a session (uploaded doc) or explicit text
        document_text = ""
        if session_id and validate_session_id(session_id) and session_id in stored_reports:
            document_text = stored_reports[session_id].get("text", "")
        else:
            document_text = data.get("document_text", "").strip()

        if not document_text:
            return jsonify({
                "error": "No document to enrich. Upload a document first or provide document_text."
            }), 400

        if not identifier:
            return jsonify({"error": "Identifier is required for enrichment"}), 400

        try:
            clean_id = sanitize_identifier(identifier, identifier_type)
        except Exception:
            clean_id = identifier

        enrich_session_id = f"enr_{uuid.uuid4().hex[:16]}"
        user_hash = _get_user_hash()

        # Phase 0: OSINT collection
        osint_client = OSINTClient()
        try:
            findings = osint_client.investigate(clean_id, depth="standard")
            findings_dict = asdict(findings)
        except Exception as exc:
            print(f"[ERROR] OSINT enrichment collection failed: {exc}")
            return jsonify({"error": "OSINT collection failed."}), 500

        osint_context = _findings_to_context(findings_dict)
        geo_context = _geo_points_to_text(findings_dict.get("geo_points", []))
        kb_context = _get_kb_context(f"enrich {clean_id} {document_text[:200]}")

        # Extract entities from document for cross-referencing
        entities_data = findings_dict.get("entities", [])
        extracted_entities = "\n".join(
            f"[{e.get('entity_type', '?')}] {e.get('entity_value', '?')}"
            for e in entities_data[:30]
        ) or "No entities extracted."

        chain = get_enrichment_chain()
        chain_input = {
            "document_text": document_text[:8000],
            "extracted_entities": extracted_entities,
            "osint_data": osint_context,
            "geo_data": geo_context,
            "kb_context": kb_context,
        }

        result = gated_invoke(
            chain,
            chain_input,
            chain_name="enrichment_chain",
            endpoint="/enrich",
            mode="osint",
            session_id=enrich_session_id,
            user_hash=user_hash,
            trusted_keys={"document_text", "osint_data", "geo_data", "kb_context"},
        )

        if not result.success:
            return jsonify({
                "error": "Request blocked by governance",
                "reason": result.reason,
                "block_id": result.block_id,
                "gate_outcome": result.gate_outcome,
            }), 403

        analysis = result.content
        sensitivity = findings_dict.get("sensitivity_level", "INTERNAL")

        report_id = _save_to_kb(
            source_route="/enrich",
            report_type="enrichment",
            analysis_text=analysis,
            subject_identifier=clean_id,
            identifier_type=identifier_type,
            sensitivity_level=sensitivity,
            entity_count=len(entities_data),
        )

        return jsonify({
            "report_id": report_id,
            "session_id": enrich_session_id,
            "analysis": analysis,
            "sensitivity_level": sensitivity,
            "identifier": clean_id,
            "entity_count": len(entities_data),
        })

    @app.route("/triangulate", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def triangulate():
        """Geolocation triangulation from multiple data points."""

        # Handle image uploads (multipart/form-data from the Images tab)
        uploaded_images = request.files.getlist("images")
        if uploaded_images:
            from app.metadata_extractor import MetadataExtractor
            from app.geo_client import GeoDataPoint as _GeoDP

            extractor = MetadataExtractor()
            image_bytes_list = []
            for f in uploaded_images:
                img_data = f.read()
                if img_data:
                    image_bytes_list.append(img_data)

            if not image_bytes_list:
                return jsonify({"error": "No valid image data received"}), 400

            geo_results = extractor.extract_geo_from_images(image_bytes_list)
            if not geo_results:
                return jsonify({
                    "error": "No GPS coordinates found in the uploaded images. "
                    "Ensure the images contain EXIF geolocation data."
                }), 400

            data_points = []
            for gp in geo_results:
                data_points.append({
                    "type": "coordinates",
                    "lat": gp["lat"],
                    "lon": gp["lon"],
                    "label": f"EXIF ({gp.get('gps_date', '')})".strip(),
                    "source": "exif",
                    "confidence": 0.95,
                })

            data = {"data_points": data_points}
            subject_context = ""
            investigation_purpose = ""
        else:
            data = request.get_json(silent=True) or {}
            data_points = data.get("data_points", [])
            subject_context = data.get("subject_context", "").strip()
            investigation_purpose = data.get("investigation_purpose", "").strip()

        if not data_points or not isinstance(data_points, list):
            return jsonify({"error": "data_points (list) is required"}), 400

        if len(data_points) > 100:
            return jsonify({"error": "Maximum 100 data points per request"}), 400

        session_id = f"tri_{uuid.uuid4().hex[:16]}"
        user_hash = _get_user_hash()

        geo_client = GeoClient()

        from app.geo_client import GeoDataPoint as GeoDP
        geo_points = []
        for dp in data_points:
            try:
                dp_type = dp.get("type", "")
                value = dp.get("value", "").strip()

                if dp_type == "ip" and value:
                    resolved = geo_client.ip_geolocate(value)
                    if resolved:
                        geo_points.append(resolved)
                    continue

                if dp_type == "address" and value:
                    resolved = geo_client.geocode(value)
                    if resolved:
                        geo_points.append(resolved)
                    continue

                if dp_type == "social_post" and value:
                    resolved = geo_client.resolve_locations([value])
                    geo_points.extend(resolved)
                    continue

                lat = dp.get("lat", dp.get("latitude"))
                lon = dp.get("lon", dp.get("lng", dp.get("longitude")))
                if lat is not None and lon is not None:
                    geo_points.append(GeoDP(
                        lat=float(lat),
                        lon=float(lon),
                        label=dp.get("label", value or ""),
                        source=dp.get("source", "user_input"),
                        confidence=float(dp.get("confidence", 0.5)),
                        timestamp=dp.get("timestamp"),
                        radius_m=float(dp.get("radius_m", 0)) if dp.get("radius_m") else None,
                        raw=dp,
                    ))
            except (ValueError, TypeError):
                continue

        if not geo_points:
            return jsonify({"error": "No valid geographic data points provided"}), 400

        # Triangulate
        triangulation = None
        try:
            triangulation = geo_client.triangulate(geo_points)
        except Exception as exc:
            print(f"[WARN] Triangulation failed (non-fatal): {exc}")

        triangulation_text = "No triangulation result available."
        if triangulation:
            tri_dict = asdict(triangulation)
            triangulation_text = (
                f"Center: ({tri_dict.get('center_lat')}, {tri_dict.get('center_lon')})\n"
                f"Radius: {tri_dict.get('radius_m')}m\n"
                f"Confidence: {tri_dict.get('confidence')}\n"
                f"Method: {tri_dict.get('method')}\n"
                f"Point count: {tri_dict.get('point_count')}"
            )

        # Build map data in the shape the frontend renderMap() expects
        map_data = {}
        try:
            markers = []
            for gp in geo_points:
                markers.append({
                    "lat": gp.lat,
                    "lng": gp.lon,
                    "label": gp.label or "",
                    "source_type": gp.source or "user_input",
                    "confidence": gp.confidence,
                    "description": gp.raw.get("city", "") if isinstance(gp.raw, dict) else "",
                })

            lats = [gp.lat for gp in geo_points]
            lons = [gp.lon for gp in geo_points]
            center = [sum(lats) / len(lats), sum(lons) / len(lons)] if lats else [20, 0]

            map_data = {
                "markers": markers,
                "center": center,
                "zoom": geo_client._auto_zoom(
                    [min(lats), min(lons)],
                    [max(lats), max(lons)],
                ) if len(lats) > 1 else 10,
            }

            if triangulation and triangulation.center_lat and triangulation.center_lon:
                source_pts = [
                    {"lat": gp.lat, "lng": gp.lon}
                    for gp in (triangulation.cluster_points or geo_points)
                ]
                map_data["triangulation"] = {
                    "center": {
                        "lat": triangulation.center_lat,
                        "lng": triangulation.center_lon,
                    },
                    "confidence_radius": triangulation.radius_m or 500,
                    "source_points": source_pts,
                    "method": triangulation.method,
                    "confidence": triangulation.confidence,
                }
        except Exception as exc:
            print(f"[WARN] Map data construction failed (non-fatal): {exc}")

        # Metadata extraction
        metadata_summary = "No metadata analysis available."
        try:
            from app.metadata_extractor import MetadataExtractor
            extractor = MetadataExtractor()
            content_items = [{"type": "geo_point", **asdict(gp)} for gp in geo_points[:20]]
            meta_results = extractor.extract_all(content_items)
            if meta_results:
                metadata_summary = "\n".join(
                    f"Source {m.source_id}: tz={m.timezone}, region={m.region}"
                    for m in meta_results[:10]
                    if m
                )
        except Exception as exc:
            print(f"[WARN] Metadata extraction failed (non-fatal): {exc}")

        geo_points_text = _geo_points_to_text([asdict(gp) for gp in geo_points])
        kb_context = _get_kb_context(f"geolocation triangulation {subject_context[:200]}")

        chain = get_geolocation_chain()
        chain_input = {
            "geo_points": geo_points_text,
            "triangulation_result": triangulation_text,
            "metadata_summary": metadata_summary,
            "subject_context": subject_context or "No additional subject context provided.",
            "elevated_authorization": _is_admin(),
        }

        result = gated_invoke(
            chain,
            chain_input,
            chain_name="geolocation_chain",
            endpoint="/triangulate",
            mode="osint",
            session_id=session_id,
            user_hash=user_hash,
            trusted_keys={"geo_points", "triangulation_result", "metadata_summary"},
        )

        if not result.success:
            return jsonify({
                "error": "Request blocked by governance",
                "reason": result.reason,
                "block_id": result.block_id,
                "gate_outcome": result.gate_outcome,
            }), 403

        analysis = result.content

        report_id = _save_to_kb(
            source_route="/triangulate",
            report_type="triangulation",
            analysis_text=analysis,
            sensitivity_level="RESTRICTED",
            tags=["geolocation", "triangulation"],
        )

        response = {
            "report_id": report_id,
            "session_id": session_id,
            "analysis": analysis,
            "map_data": map_data,
            "point_count": len(geo_points),
            "sensitivity_level": "RESTRICTED",
        }
        if triangulation:
            response["triangulation"] = asdict(triangulation)

        return jsonify(response)

    @app.route("/batch-investigate", methods=["POST"])
    @login_required
    @limiter.limit("5 per hour")
    def batch_investigate():
        """Batch OSINT investigation for multiple identifiers."""
        data = request.get_json(silent=True) or {}
        identifiers = data.get("identifiers", [])
        depth = data.get("depth", "quick").strip().lower()

        if not identifiers or not isinstance(identifiers, list):
            return jsonify({"error": "identifiers list is required"}), 400

        batch_limit = 500 if _is_admin() else 50
        if len(identifiers) > batch_limit:
            return jsonify({"error": f"Maximum {batch_limit} identifiers per batch"}), 400

        if depth not in INVESTIGATION_DEPTHS:
            depth = "quick"

        session_id = f"batch_{uuid.uuid4().hex[:16]}"
        user_hash = _get_user_hash()

        # Validate each identifier
        valid_items = []
        invalid_items = []
        for item in identifiers:
            if isinstance(item, dict):
                ident = item.get("identifier", "").strip()
                id_type = item.get("identifier_type", "username").strip().lower()
            elif isinstance(item, str):
                ident = item.strip()
                id_type = "username"
            else:
                continue

            if not ident:
                invalid_items.append({"identifier": ident, "error": "Empty identifier"})
                continue
            if id_type not in IDENTIFIER_TYPES:
                id_type = "username"

            valid_items.append({"identifier": ident, "identifier_type": id_type})

        if not valid_items:
            return jsonify({"error": "No valid identifiers provided"}), 400

        # Process in parallel
        osint_client = OSINTClient()
        geo_client = GeoClient()
        platforms = list(SOCIAL_PLATFORMS.keys())

        elevated = _is_admin()
        with ThreadPoolExecutor(max_workers=min(8, len(valid_items))) as executor:
            futures = {
                executor.submit(
                    _process_single_identifier,
                    item["identifier"],
                    item["identifier_type"],
                    platforms,
                    depth,
                    osint_client,
                    geo_client,
                    session_id,
                    user_hash,
                    elevated,
                ): item
                for item in valid_items
            }
            item_results = []
            for future in as_completed(futures):
                item_results.append(future.result())

        # Maintain input order
        ident_order = [item["identifier"] for item in valid_items]
        item_results.sort(
            key=lambda r: ident_order.index(r.get("identifier", ""))
            if r.get("identifier", "") in ident_order else len(ident_order)
        )

        successful = [r for r in item_results if r.get("success")]
        failed = [r for r in item_results if not r.get("success")]

        # Cross-entity synthesis
        consolidated_analysis = ""
        if successful:
            per_entity_summaries = "\n---\n".join(
                f"### {r['identifier']} ({r['identifier_type']})\n{r['analysis']}"
                for r in successful
            )
            kb_context = _get_kb_context(
                " ".join(r["identifier"] for r in successful)[:500] or "batch investigation"
            )

            chain = get_batch_synthesis_chain()
            chain_input = {
                "per_entity_summaries": per_entity_summaries,
                "aggregate_osint": f"{len(successful)} entities analyzed in batch.",
                "cross_entity_relationships": "Cross-entity analysis pending (Phase 0).",
                "geo_aggregate": "Geographic aggregate data pending (Phase 0).",
                "elevated_authorization": _is_admin(),
            }

            try:
                synth_result = gated_invoke(
                    chain=chain,
                    chain_input=chain_input,
                    chain_name="batch_synthesis_chain",
                    endpoint="/batch-investigate",
                    session_id=session_id,
                    mode="osint",
                    user_hash=user_hash,
                    trusted_keys={"per_entity_summaries", "aggregate_osint"},
                )
                if synth_result.success:
                    consolidated_analysis = synth_result.content
                else:
                    consolidated_analysis = f"[Synthesis blocked: {synth_result.reason}]"
            except Exception as exc:
                consolidated_analysis = f"[Synthesis failed: {str(exc)[:200]}]"

        # Save consolidated analysis
        report_id = None
        if consolidated_analysis and not consolidated_analysis.startswith("["):
            report_id = _save_to_kb(
                source_route="/batch-investigate",
                report_type="batch",
                analysis_text=consolidated_analysis,
                subject_identifier=f"Batch: {len(successful)} entities",
                entity_count=sum(r.get("entity_count", 0) for r in successful),
                tags=["batch"],
            )

        return jsonify({
            "report_id": report_id,
            "session_id": session_id,
            "consolidated_analysis": consolidated_analysis,
            "item_results": item_results,
            "summary": {
                "total": len(valid_items),
                "successful": len(successful),
                "failed": len(failed),
                "invalid": invalid_items,
            },
        })

    @app.route("/scenario", methods=["POST"])
    @login_required
    @limiter.limit("20 per hour")
    def scenario():
        """Generate analytical scenarios from OSINT data."""
        data = request.get_json(silent=True) or {}
        scenario_type = data.get("scenario_type", "").strip().lower()
        osint_data = data.get("osint_data", "").strip()
        subject_context = data.get("subject_context", "").strip()
        investigation_purpose = data.get("investigation_purpose", "").strip()
        session_id = data.get("session_id")

        if scenario_type not in SCENARIO_TYPES:
            return jsonify({
                "error": f"Invalid scenario_type. Must be one of: {', '.join(SCENARIO_TYPES.keys())}"
            }), 400

        # Build OSINT context from session or provided data
        if not osint_data and session_id and validate_session_id(session_id) and session_id in stored_reports:
            osint_data = stored_reports[session_id].get("text", "")[:5000]

        if not osint_data:
            kb_osint = _get_kb_context(f"scenario {scenario_type} analysis")
            if not kb_osint:
                return jsonify({
                    "error": "No OSINT data available. Run an investigation or provide osint_data."
                }), 400
            osint_data = kb_osint

        kb_context = _get_kb_context(f"{scenario_type} {subject_context[:200]}")

        scenario_session_id = session_id or f"scn_{uuid.uuid4().hex[:16]}"
        user_hash = _get_user_hash()

        chain = get_scenario_chain()
        chain_input = {
            "scenario_type": scenario_type,
            "osint_data": osint_data,
            "subject_context": subject_context or "No additional subject context provided.",
            "kb_context": kb_context,
        }

        result = gated_invoke(
            chain,
            chain_input,
            chain_name="scenario_chain",
            endpoint="/scenario",
            mode="osint",
            session_id=scenario_session_id,
            user_hash=user_hash,
            trusted_keys={"osint_data", "kb_context"},
        )

        if not result.success:
            return jsonify({
                "error": "Request blocked by governance",
                "reason": result.reason,
                "block_id": result.block_id,
                "gate_outcome": result.gate_outcome,
            }), 403

        analysis = result.content

        report_id = _save_to_kb(
            source_route="/scenario",
            report_type="scenario",
            analysis_text=analysis,
            tags=[scenario_type, "scenario"],
        )

        return jsonify({
            "report_id": report_id,
            "session_id": scenario_session_id,
            "scenario": analysis,
            "scenario_type": scenario_type,
        })

    # ================================================================
    #  EXPORT ROUTES
    # ================================================================

    def _resolve_export_data(data: dict) -> dict:
        """Merge export request data with stored report data.

        When the frontend sends only a session_id, look up the cached
        analysis text, entities, and sensitivity from stored_reports so
        export routes have everything they need.
        """
        sid = data.get("session_id", "")
        if sid and validate_session_id(sid) and sid in stored_reports:
            cached = stored_reports[sid]
            if not data.get("content"):
                data["content"] = cached.get("text", "")
            if not data.get("entities"):
                data["entities"] = cached.get("entities", [])
            if not data.get("sensitivity_level"):
                data["sensitivity_level"] = cached.get("sensitivity_level", "INTERNAL")
            if not data.get("title"):
                identifier = cached.get("identifier", "")
                if identifier:
                    data["title"] = f"Fortis Report — {identifier}"
            if not data.get("chart_data"):
                data["chart_data"] = cached.get("chart_data")
            if not data.get("investigation"):
                data["investigation"] = {
                    "identifier": cached.get("identifier", ""),
                    "sensitivity_level": cached.get("sensitivity_level", "INTERNAL"),
                }
        return data

    @app.route("/export/pdf", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_pdf():
        """Generate a styled PDF from analysis text, charts, and map snapshot."""
        data = _resolve_export_data(request.get_json(silent=True) or {})
        content = data.get("content", "")
        title = data.get("title", "Fortis Intelligence Report")
        export_session_id = data.get("session_id", "")
        sensitivity_level = data.get("sensitivity_level", "INTERNAL")
        map_snapshot_b64 = data.get("map_snapshot")

        if not content or not content.strip():
            return jsonify({"error": "No content provided"}), 400
        if len(content) > 500_000 and not _is_admin():
            return jsonify({"error": "Content too large for export"}), 400

        title = re.sub(r"[^\w\s\-]", "", title)[:100] or "Fortis Intelligence Report"

        # Build charts from chart_data if provided
        charts = None
        chart_data = data.get("chart_data")
        if chart_data and isinstance(chart_data, dict):
            try:
                findings = chart_data.get("findings", [])
                entities = chart_data.get("entities", [])
                if findings or entities:
                    charts = generate_investigation_charts(findings, entities)
            except Exception as exc:
                print(f"[WARN] Chart generation for PDF failed (non-fatal): {exc}")

        try:
            pdf_bytes = generate_pdf(
                content, title, export_session_id,
                charts=charts,
                sensitivity_level=sensitivity_level,
                map_snapshot_b64=map_snapshot_b64,
            )
        except Exception as exc:
            print(f"[ERROR] PDF export failed: {exc}")
            return jsonify({"error": "PDF generation failed"}), 500

        safe_filename = re.sub(r"\s+", "_", title)[:50] + ".pdf"
        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
        response.headers["Content-Length"] = len(pdf_bytes)
        return response

    @app.route("/export/markdown", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_markdown():
        """Generate a Markdown export of analysis text."""
        data = _resolve_export_data(request.get_json(silent=True) or {})
        content = data.get("content", "")
        title = data.get("title", "Fortis Intelligence Report")
        export_session_id = data.get("session_id", "")

        if not content or not content.strip():
            return jsonify({"error": "No content provided"}), 400
        if len(content) > 500_000 and not _is_admin():
            return jsonify({"error": "Content too large for export"}), 400

        title = re.sub(r"[^\w\s\-]", "", title)[:100] or "Fortis Intelligence Report"

        try:
            md_bytes = generate_markdown(content, title, export_session_id)
        except Exception as exc:
            print(f"[ERROR] Markdown export failed: {exc}")
            return jsonify({"error": "Markdown generation failed"}), 500

        safe_filename = re.sub(r"\s+", "_", title)[:50] + ".md"
        response = make_response(md_bytes)
        response.headers["Content-Type"] = "text/markdown"
        response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
        return response

    @app.route("/export/stix", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_stix():
        """Export OSINT entities in STIX 2.1 format."""
        data = _resolve_export_data(request.get_json(silent=True) or {})
        entities = data.get("entities")
        investigation = data.get("investigation")

        if not entities or not isinstance(entities, list):
            return jsonify({"error": "No entity data provided"}), 400

        try:
            stix_bundle = convert_to_stix21(entities, investigation)
            stix_json = _json.dumps(stix_bundle, indent=2)

            subject = (investigation or {}).get("identifier", "export")
            safe_filename = re.sub(r"[^\w\-]", "_", str(subject))[:40] + ".stix.json"

            response = make_response(stix_json)
            response.headers["Content-Type"] = "application/json"
            response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
            return response
        except Exception as exc:
            print(f"[ERROR] STIX export failed: {exc}")
            return jsonify({"error": "STIX export failed"}), 500

    @app.route("/export/csv", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_csv():
        """Export OSINT entities in CSV format."""
        data = _resolve_export_data(request.get_json(silent=True) or {})
        entities = data.get("entities")

        if not entities or not isinstance(entities, list):
            return jsonify({"error": "No entity data provided"}), 400

        try:
            csv_data = convert_to_csv(entities)

            response = make_response(csv_data)
            response.headers["Content-Type"] = "text/csv"
            response.headers["Content-Disposition"] = 'attachment; filename="entities_export.csv"'
            return response
        except Exception as exc:
            print(f"[ERROR] CSV export failed: {exc}")
            return jsonify({"error": "CSV export failed"}), 500

    @app.route("/export/json", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_json_route():
        """Export OSINT entities in structured JSON format."""
        data = _resolve_export_data(request.get_json(silent=True) or {})
        entities = data.get("entities")
        investigation = data.get("investigation")

        if not entities or not isinstance(entities, list):
            return jsonify({"error": "No entity data provided"}), 400

        try:
            json_data = convert_to_json(entities, investigation)

            response = make_response(json_data)
            response.headers["Content-Type"] = "application/json"
            response.headers["Content-Disposition"] = 'attachment; filename="entities_export.json"'
            return response
        except Exception as exc:
            print(f"[ERROR] JSON export failed: {exc}")
            return jsonify({"error": "JSON export failed"}), 500

    # ── Google Drive export ────────────────────────────────────────

    def _drive_upload_or_503(file_bytes, filename, mime_type):
        """Upload bytes to Google Drive or return 503 if not configured."""
        client = get_gdrive_client()
        if not client.is_configured:
            return jsonify({
                "error": "Google Drive not configured. "
                         "Set GDRIVE_SERVICE_ACCOUNT_KEY_FILE and GDRIVE_FOLDER_ID in .env"
            }), 503
        result = client.upload_file(file_bytes, filename, mime_type)
        if result["success"]:
            user_hash = _get_user_hash()
            print(f"[AUDIT] Drive upload: user={user_hash} file={filename} id={result.get('file_id')}")
            return jsonify(result)
        return jsonify({"error": result.get("error", "Upload failed")}), 500

    @app.route("/export/drive/<format_type>", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_drive(format_type):
        """Upload an export to Google Drive."""
        if format_type not in ("pdf", "markdown", "stix", "csv", "json"):
            return jsonify({"error": "Invalid format. Use: pdf, markdown, stix, csv, json"}), 400

        data = _resolve_export_data(request.get_json(silent=True) or {})
        sensitivity = data.get("sensitivity_level", "INTERNAL")
        sens_tag = sensitivity.replace(" ", "_")

        if format_type == "pdf":
            content = data.get("content", "")
            title = data.get("title", "Fortis Intelligence Report")
            export_session_id = data.get("session_id", "")
            map_snapshot_b64 = data.get("map_snapshot")

            if not content or not content.strip():
                return jsonify({"error": "No content provided"}), 400
            if len(content) > 500_000:
                return jsonify({"error": "Content too large"}), 400

            title = re.sub(r"[^\w\s\-]", "", title)[:100] or "Fortis Report"

            charts = None
            chart_data = data.get("chart_data")
            if chart_data and isinstance(chart_data, dict):
                try:
                    charts = generate_investigation_charts(
                        chart_data.get("findings", []),
                        chart_data.get("entities", []),
                    )
                except Exception:
                    pass

            try:
                file_bytes = generate_pdf(
                    content, title, export_session_id,
                    charts=charts,
                    sensitivity_level=sensitivity,
                    map_snapshot_b64=map_snapshot_b64,
                )
            except Exception as exc:
                print(f"[ERROR] Drive PDF generation failed: {exc}")
                return jsonify({"error": "PDF generation failed"}), 500

            safe_filename = re.sub(r"\s+", "_", title)[:50] + f"_{sens_tag}.pdf"
            return _drive_upload_or_503(file_bytes, safe_filename, "application/pdf")

        elif format_type == "markdown":
            content = data.get("content", "")
            title = data.get("title", "Fortis Intelligence Report")
            export_session_id = data.get("session_id", "")

            if not content or not content.strip():
                return jsonify({"error": "No content provided"}), 400
            if len(content) > 500_000:
                return jsonify({"error": "Content too large"}), 400

            title = re.sub(r"[^\w\s\-]", "", title)[:100] or "Fortis Report"

            try:
                file_bytes = generate_markdown(content, title, export_session_id)
            except Exception as exc:
                print(f"[ERROR] Drive Markdown generation failed: {exc}")
                return jsonify({"error": "Markdown generation failed"}), 500

            safe_filename = re.sub(r"\s+", "_", title)[:50] + f"_{sens_tag}.md"
            return _drive_upload_or_503(file_bytes, safe_filename, "text/markdown")

        elif format_type == "stix":
            entities = data.get("entities")
            investigation = data.get("investigation")
            if not entities or not isinstance(entities, list):
                return jsonify({"error": "No entity data provided"}), 400
            try:
                stix_bundle = convert_to_stix21(entities, investigation)
                file_bytes = _json.dumps(stix_bundle, indent=2).encode("utf-8")
            except Exception as exc:
                print(f"[ERROR] Drive STIX generation failed: {exc}")
                return jsonify({"error": "STIX generation failed"}), 500

            subject = (investigation or {}).get("identifier", "export")
            safe_filename = re.sub(r"[^\w\-]", "_", str(subject))[:40] + f"_{sens_tag}.stix.json"
            return _drive_upload_or_503(file_bytes, safe_filename, "application/json")

        elif format_type == "csv":
            entities = data.get("entities")
            if not entities or not isinstance(entities, list):
                return jsonify({"error": "No entity data provided"}), 400
            try:
                csv_data = convert_to_csv(entities)
                file_bytes = csv_data.encode("utf-8") if isinstance(csv_data, str) else csv_data
            except Exception as exc:
                print(f"[ERROR] Drive CSV generation failed: {exc}")
                return jsonify({"error": "CSV generation failed"}), 500

            safe_filename = f"entities_{sens_tag}.csv"
            return _drive_upload_or_503(file_bytes, safe_filename, "text/csv")

        else:  # json
            entities = data.get("entities")
            investigation = data.get("investigation")
            if not entities or not isinstance(entities, list):
                return jsonify({"error": "No entity data provided"}), 400
            try:
                json_str = convert_to_json(entities, investigation)
                file_bytes = json_str.encode("utf-8") if isinstance(json_str, str) else json_str
            except Exception as exc:
                print(f"[ERROR] Drive JSON generation failed: {exc}")
                return jsonify({"error": "JSON generation failed"}), 500

            safe_filename = f"entities_{sens_tag}.json"
            return _drive_upload_or_503(file_bytes, safe_filename, "application/json")

    @app.route("/export/map-snapshot", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_map_snapshot():
        """Save a map PNG from frontend base64 data."""
        data = request.get_json(silent=True) or {}
        image_b64 = data.get("image")
        snapshot_session_id = data.get("session_id", uuid.uuid4().hex[:16])

        if not image_b64:
            return jsonify({"error": "No image data provided"}), 400

        # Strip data URI prefix if present
        if "," in image_b64:
            image_b64 = image_b64.split(",", 1)[1]

        try:
            image_bytes = base64.b64decode(image_b64)
        except Exception:
            return jsonify({"error": "Invalid base64 image data"}), 400

        if len(image_bytes) > 10 * 1024 * 1024:  # 10 MB limit
            return jsonify({"error": "Image too large (max 10 MB)"}), 400

        snapshot_dir = DATA_DIR / "map_snapshots"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        filename = f"map_{snapshot_session_id}_{uuid.uuid4().hex[:8]}.png"
        filepath = snapshot_dir / filename

        filepath.write_bytes(image_bytes)

        return jsonify({
            "success": True,
            "filename": filename,
            "size_bytes": len(image_bytes),
        })

    # ================================================================
    #  KNOWLEDGE BASE ROUTES
    # ================================================================

    @app.route("/kb/reports", methods=["GET"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_list_reports():
        """List reports with pagination and filtering."""
        page = request.args.get("page", 1, type=int)
        per_page = min(request.args.get("per_page", 20, type=int), 100)
        report_type = request.args.get("type")
        in_kb = request.args.get("in_kb")
        sensitivity_level = request.args.get("sensitivity_level")
        identifier_type = request.args.get("identifier_type")

        if in_kb is not None:
            in_kb = in_kb.lower() == "true"

        store = get_report_store()
        offset = (page - 1) * per_page
        reports = store.list_reports(
            limit=per_page,
            offset=offset,
            report_type=report_type,
            in_kb=in_kb,
            sensitivity_level=sensitivity_level,
            identifier_type=identifier_type,
        )
        total = store.count()

        return jsonify({
            "reports": [
                {k: v for k, v in asdict(r).items() if k != "analysis_text"}
                for r in reports
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
        })

    @app.route("/kb/reports/<report_id>", methods=["GET"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_get_report(report_id: str):
        """Get a specific report by ID."""
        store = get_report_store()
        report = store.get(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404
        return jsonify(asdict(report))

    @app.route("/kb/reports/<report_id>", methods=["DELETE"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_delete_report(report_id: str):
        """Delete a report and rebuild KB if it was indexed."""
        store = get_report_store()
        report = store.get(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404

        store.delete(report_id)
        if report.in_knowledge_base:
            _rebuild_kb_from_store()

        return jsonify({"message": "Report deleted"})

    @app.route("/kb/reports/<report_id>/toggle", methods=["POST"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_toggle_report(report_id: str):
        """Toggle a report in or out of the knowledge base."""
        store = get_report_store()
        report = store.get(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404

        new_state = not report.in_knowledge_base
        store.toggle_kb(report_id, new_state)
        _rebuild_kb_from_store()

        return jsonify({"in_knowledge_base": new_state})

    @app.route("/kb/stats", methods=["GET"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_stats():
        """Return knowledge base statistics."""
        store = get_report_store()
        stats = store.get_stats()
        stats["kb_exists"] = knowledge_base_exists()
        stats["retention_days"] = int(os.getenv("KB_RETENTION_DAYS", "90"))
        return jsonify(stats)

    @app.route("/kb/rebuild", methods=["POST"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_rebuild():
        """Force a full rebuild of the FAISS knowledge base."""
        store = get_report_store()
        archived = store.archive_stale()
        count = _rebuild_kb_from_store()
        return jsonify({
            "message": "KB rebuilt",
            "total_chunks": count,
            "stale_archived": archived,
        })

    # ================================================================
    #  FORGECHAIN ROUTES
    # ================================================================

    @app.route("/forge/session/<session_id>/replay", methods=["GET"])
    @login_required
    def forge_replay(session_id):
        """Return forensic replay data for a ForgeChain session."""
        if not validate_session_id(session_id):
            return jsonify({"error": "Invalid session ID"}), 400

        endpoint_filter = request.args.get("endpoint")
        outcome_filter = request.args.get("outcome")

        replay_data = get_session_replay(
            session_id=session_id,
            endpoint_filter=endpoint_filter,
            outcome_filter=outcome_filter,
        )

        if replay_data is None:
            return jsonify({"error": "Session not found in ForgeChain"}), 404

        return jsonify(replay_data)

    @app.route("/forge/session/<session_id>/verify", methods=["GET"])
    @login_required
    def forge_verify(session_id):
        """Verify the cryptographic integrity of a ForgeChain session."""
        if not validate_session_id(session_id):
            return jsonify({"error": "Invalid session ID"}), 400

        store = get_chain_store()
        chain_session = store.load_session(session_id)

        if chain_session is None:
            return jsonify({"error": "Session not found"}), 404

        is_valid, error = chain_session.verify_integrity()
        return jsonify({
            "session_id": session_id,
            "chain_valid": is_valid,
            "block_count": len(chain_session.blocks),
            "error": error,
        })

    @app.route("/forge/health", methods=["GET"])
    @login_required
    def forge_health():
        """Return ForgeChain health and statistics."""
        store = get_chain_store()
        stats = store.get_stats()
        return jsonify({
            "forge_enabled": FORGE_ENABLED,
            "total_sessions": stats["total_sessions"],
            "total_blocks": stats["total_blocks"],
            "last_activity": stats["last_block_timestamp"],
        })

    # ================================================================
    #  MONITOR ROUTES (Phase 0)
    # ================================================================

    @app.route("/monitor/create", methods=["POST"])
    @login_required
    @limiter.limit("10 per hour")
    def monitor_create():
        """Create a new feed monitor."""
        data = request.get_json(silent=True) or {}
        query = data.get("query", "").strip()
        monitor_type = data.get("monitor_type", "keyword").strip()
        platforms = data.get("platforms", [])
        interval_minutes = data.get("interval_minutes", 60)
        alert_threshold = data.get("alert_threshold", "all")

        if not query:
            return jsonify({"error": "Query is required"}), 400
        if len(query) > 500:
            return jsonify({"error": "Query too long (max 500 characters)"}), 400

        user_hash = _get_user_hash()

        config = {
            "query": query,
            "monitor_type": monitor_type,
            "platforms": platforms,
            "interval_minutes": interval_minutes,
            "alert_threshold": alert_threshold,
            "created_by": user_hash,
        }

        try:
            monitor = FeedMonitor()
            result = monitor.create_monitor(config)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Monitor creation failed: {exc}")
            return jsonify({"error": "Failed to create monitor"}), 500

    @app.route("/monitor/<monitor_id>/pause", methods=["POST"])
    @login_required
    def monitor_pause(monitor_id):
        """Pause a feed monitor."""
        try:
            monitor = FeedMonitor()
            result = monitor.pause_monitor(monitor_id)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Monitor pause failed: {exc}")
            return jsonify({"error": "Failed to pause monitor"}), 500

    @app.route("/monitor/<monitor_id>/resume", methods=["POST"])
    @login_required
    def monitor_resume(monitor_id):
        """Resume a paused feed monitor."""
        try:
            monitor = FeedMonitor()
            result = monitor.resume_monitor(monitor_id)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Monitor resume failed: {exc}")
            return jsonify({"error": "Failed to resume monitor"}), 500

    @app.route("/monitor/<monitor_id>/delete", methods=["DELETE"])
    @login_required
    def monitor_delete(monitor_id):
        """Delete a feed monitor."""
        try:
            monitor = FeedMonitor()
            result = monitor.delete_monitor(monitor_id)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Monitor deletion failed: {exc}")
            return jsonify({"error": "Failed to delete monitor"}), 500

    @app.route("/monitor/list", methods=["GET"])
    @login_required
    def monitor_list():
        """List all feed monitors."""
        try:
            monitor = FeedMonitor()
            monitors = monitor.list_monitors()
            return jsonify({"monitors": monitors})
        except Exception as exc:
            print(f"[ERROR] Monitor list failed: {exc}")
            return jsonify({"error": "Failed to list monitors"}), 500

    @app.route("/monitor/watch", methods=["GET"])
    @login_required
    def monitor_watch():
        """List pending findings from feed monitors."""
        try:
            monitor = FeedMonitor()
            findings = monitor.get_pending_findings()
            return jsonify({"findings": findings})
        except Exception as exc:
            print(f"[ERROR] Monitor watch failed: {exc}")
            return jsonify({"error": "Failed to fetch findings"}), 500

    @app.route("/monitor/<finding_id>/approve", methods=["POST"])
    @login_required
    def monitor_approve(finding_id):
        """Approve a monitor finding for further investigation."""
        try:
            monitor = FeedMonitor()
            result = monitor.approve_finding(finding_id)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Finding approval failed: {exc}")
            return jsonify({"error": "Failed to approve finding"}), 500

    @app.route("/monitor/<finding_id>/dismiss", methods=["POST"])
    @login_required
    def monitor_dismiss(finding_id):
        """Dismiss a monitor finding."""
        data = request.get_json(silent=True) or {}
        reason = data.get("reason")

        try:
            monitor = FeedMonitor()
            result = monitor.dismiss_finding(finding_id, reason=reason)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Finding dismissal failed: {exc}")
            return jsonify({"error": "Failed to dismiss finding"}), 500

    # ================================================================
    #  UTILITY ROUTES
    # ================================================================

    @app.route("/osint-status", methods=["GET"])
    def osint_status():
        """Check OSINT source availability and return platform status."""
        configured = []
        unconfigured = []

        for platform, config in SOCIAL_PLATFORMS.items():
            env_keys = config.get("env_keys", [])
            if not env_keys:
                single_key = config.get("env_key", f"{platform.upper()}_API_KEY")
                env_keys = [single_key]
            name = config.get("name", platform)
            if all(bool(os.getenv(k)) for k in env_keys):
                configured.append(name)
            else:
                unconfigured.append(name)

        return jsonify({
            "configured": configured,
            "unconfigured": unconfigured,
        })

    # ================================================================
    #  ADMIN ROUTES
    # ================================================================

    @app.route("/admin/sessions", methods=["GET"])
    @login_required
    @admin_required
    def admin_sessions():
        """List all active sessions (admin only)."""
        sessions_list = []
        for token, user_sess in session_manager.sessions.items():
            sessions_list.append({
                "email": user_sess.email,
                "name": user_sess.name,
                "is_admin": user_sess.is_admin,
                "created_at": user_sess.created_at.isoformat(),
                "last_activity": user_sess.last_activity.isoformat(),
                "token_prefix": token[:8],
            })
        sessions_list.sort(key=lambda s: s["last_activity"], reverse=True)
        return jsonify({"sessions": sessions_list, "total": len(sessions_list)})

    @app.route("/admin/sessions/<token_prefix>", methods=["DELETE"])
    @login_required
    @admin_required
    def admin_kill_session(token_prefix):
        """Terminate a session by token prefix (admin only)."""
        if not token_prefix or len(token_prefix) < 8:
            return jsonify({"error": "Token prefix must be at least 8 characters"}), 400

        for token in list(session_manager.sessions.keys()):
            if token.startswith(token_prefix):
                target = session_manager.sessions[token]
                if target.email == g.user_session.email:
                    return jsonify({"error": "Cannot terminate your own session"}), 400
                session_manager.invalidate_session(token)
                audit_logger = get_audit_logger()
                audit_logger._log_event("ADMIN_SESSION_KILL", {
                    "admin": g.user_session.email,
                    "target_email": target.email,
                })
                return jsonify({"success": True, "killed_email": target.email})

        return jsonify({"error": "Session not found"}), 404

    @app.route("/admin/stats", methods=["GET"])
    @login_required
    @admin_required
    def admin_stats():
        """System statistics (admin only)."""
        report_store = get_report_store()
        reports = report_store.list_reports(limit=0)

        return jsonify({
            "active_sessions": len(session_manager.sessions),
            "cached_reports": len(stored_reports),
            "kb_reports": len(reports),
            "admin_emails": sorted(ADMIN_EMAILS),
            "forge_enabled": os.getenv("FORGE_ENABLED", "true").lower() == "true",
            "auth_enabled": AUTH_ENABLED,
            "vectorstore_exists": VECTORSTORE_DIR.is_dir() and any(VECTORSTORE_DIR.iterdir()) if VECTORSTORE_DIR.is_dir() else False,
        })

    @app.route("/admin/config", methods=["GET"])
    @login_required
    @admin_required
    def admin_config():
        """View non-secret configuration (admin only)."""
        return jsonify({
            "auth_enabled": AUTH_ENABLED,
            "forge_enabled": os.getenv("FORGE_ENABLED", "true").lower() == "true",
            "forge_healing_enabled": os.getenv("FORGE_HEALING_ENABLED", "true").lower() == "true",
            "session_timeout_minutes": SESSION_TIMEOUT_MINUTES,
            "max_upload_mb_regular": 50,
            "max_upload_mb_admin": 200,
            "max_batch_regular": 50,
            "max_batch_admin": 500,
            "admin_count": len(ADMIN_EMAILS),
            "redis_configured": bool(os.getenv("REDIS_URL")),
            "flask_env": os.getenv("FLASK_ENV", "development"),
        })

    @app.route("/admin/audit", methods=["GET"])
    @login_required
    @admin_required
    def admin_audit():
        """Read recent audit log entries (admin only)."""
        limit = min(int(request.args.get("limit", 100)), 500)
        log_path = LOG_DIR / "audit.log"
        if not log_path.exists():
            return jsonify({"entries": [], "total": 0})

        lines = log_path.read_text(encoding="utf-8", errors="replace").strip().split("\n")
        entries = []
        for line in lines[-limit:]:
            try:
                entries.append(_json.loads(line))
            except _json.JSONDecodeError:
                continue
        entries.reverse()
        return jsonify({"entries": entries, "total": len(lines)})

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint for container orchestration and monitoring."""
        components = {}

        # LLM: check if DeepSeek API key is configured
        components["llm"] = bool(os.getenv("DEEPSEEK_API_KEY"))

        # Redis: try a ping
        try:
            import redis as _redis
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            r = _redis.from_url(redis_url, socket_connect_timeout=2)
            r.ping()
            components["redis"] = True
        except Exception:
            components["redis"] = False

        # Vectorstore: check if the KB directory exists and has content
        components["vectorstore"] = VECTORSTORE_DIR.is_dir() and any(VECTORSTORE_DIR.iterdir())

        overall = "healthy" if any(components.values()) else "degraded"
        return jsonify({
            "status": overall,
            "version": "1.0.0",
            "components": components,
        })

    @app.route("/gdrive-status", methods=["GET"])
    def gdrive_status():
        """Check Google Drive configuration status."""
        client = get_gdrive_client()
        return jsonify({"configured": client.is_configured})

    # ================================================================
    #  STARTUP TASKS
    # ================================================================

    # Verify KB integrity on startup
    if not verify_kb_on_startup():
        print("[STARTUP] Rebuilding KB from ReportStore...")
        try:
            _rebuild_kb_from_store()
        except Exception as exc:
            print(f"[STARTUP] KB rebuild failed: {exc}")

    # Archive stale KB reports
    try:
        store = get_report_store()
        archived = store.archive_stale()
        if archived > 0:
            print(f"[STARTUP] Archived {archived} stale reports, rebuilding KB...")
            _rebuild_kb_from_store()
    except Exception as exc:
        print(f"[STARTUP] KB retention cleanup failed: {exc}")

    # Check OSINT source availability
    try:
        available_count = 0
        for platform, config in SOCIAL_PLATFORMS.items():
            env_keys = config.get("env_keys", [])
            if not env_keys:
                single_key = config.get("env_key", f"{platform.upper()}_API_KEY")
                env_keys = [single_key]
            if all(bool(os.getenv(k)) for k in env_keys):
                available_count += 1
                print(f"[STARTUP] OSINT source available: {platform}")
        if available_count == 0:
            print("[STARTUP] No OSINT API keys configured (Phase 0 stub mode)")
        else:
            print(f"[STARTUP] {available_count}/{len(SOCIAL_PLATFORMS)} OSINT sources configured")
    except Exception as exc:
        print(f"[STARTUP] OSINT availability check failed: {exc}")

    return app

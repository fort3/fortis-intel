"""FAISS-backed vector store for per-upload document retrieval and the
persistent Knowledge Base (KB).

Embedding model: BAAI/bge-base-en-v1.5 (768 dimensions).
BGE models use instruction-aware prefixes — a query instruction is prepended
to queries so the model distinguishes retrieval queries from raw passages.

Security: every persisted vectorstore directory gets an HMAC integrity tag
(SHA-256 keyed by VECTORSTORE_HMAC_KEY) that is verified before loading.
"""

import hashlib
import hmac
import os
import threading

from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

from app.utils.uploads import validate_session_id

VECTOR_DIR = "vectorstores"
os.makedirs(VECTOR_DIR, exist_ok=True)

_HMAC_FILENAME = "integrity.hmac"

# BGE embedding configuration
_BGE_MODEL_NAME = "BAAI/bge-base-en-v1.5"
_BGE_QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "


# ── HMAC integrity helpers ──────────────────────────────────────────

def _get_hmac_key() -> bytes:
    key = os.getenv("VECTORSTORE_HMAC_KEY", "")
    if not key:
        key = os.getenv("SESSION_SECRET_KEY", "vectorstore-dev-hmac-key")
    return key.encode()


def _compute_dir_hmac(directory: str) -> str:
    h = hmac.new(_get_hmac_key(), digestmod=hashlib.sha256)
    for fname in sorted(os.listdir(directory)):
        if fname == _HMAC_FILENAME:
            continue
        fpath = os.path.join(directory, fname)
        if os.path.isfile(fpath):
            h.update(fname.encode())
            with open(fpath, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
    return h.hexdigest()


def _write_hmac(directory: str) -> None:
    digest = _compute_dir_hmac(directory)
    with open(os.path.join(directory, _HMAC_FILENAME), "w") as f:
        f.write(digest)


def _verify_hmac(directory: str) -> bool:
    hmac_path = os.path.join(directory, _HMAC_FILENAME)
    if not os.path.exists(hmac_path):
        print(f"  [WARN] No integrity HMAC found for vectorstore at {directory}")
        return True
    with open(hmac_path, "r") as f:
        stored = f.read().strip()
    computed = _compute_dir_hmac(directory)
    return hmac.compare_digest(stored, computed)


# ── Embedder (lazy singleton) ──────────────────────────────────────

_embedder = None
_embedder_error = None


def get_embedder():
    """Lazy-load the BGE embedding model.

    Uses BAAI/bge-base-en-v1.5 (768-dim) with normalized embeddings
    and query instruction prefix for retrieval tasks.
    """
    global _embedder, _embedder_error
    if _embedder is None and _embedder_error is None:
        try:
            _embedder = HuggingFaceEmbeddings(
                model_name=_BGE_MODEL_NAME,
                model_kwargs={"device": "cpu"},
                encode_kwargs={"normalize_embeddings": True},
            )
        except Exception as exc:
            _embedder_error = str(exc)
            print(f"Error loading embeddings: {exc}")
            raise

    if _embedder_error:
        raise RuntimeError(f"Embedder initialization failed: {_embedder_error}")

    return _embedder


# ── Per-upload vectorstore ──────────────────────────────────────────

def _vector_path(session_id: str) -> str:
    if not validate_session_id(session_id):
        raise ValueError("Invalid session ID")
    return os.path.join(VECTOR_DIR, session_id)


def build_vectorstore(text, session_id):
    """Build a FAISS vectorstore from text for a given upload session."""
    try:
        if not text or len(text.strip()) == 0:
            print(f"Warning: Empty text for session {session_id}, skipping vectorstore")
            return

        splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=150)
        chunks = splitter.split_text(text)

        if not chunks:
            print(f"Warning: No chunks generated for session {session_id}, skipping vectorstore")
            return

        vs = FAISS.from_texts(chunks, get_embedder())
        vs.save_local(_vector_path(session_id))
        _write_hmac(_vector_path(session_id))
        print(
            f"Vectorstore built successfully for session {session_id} with {len(chunks)} chunks"
        )
    except Exception as exc:
        print(f"Error building vectorstore: {exc}")
        raise


def load_vectorstore(session_id):
    """Load a previously built FAISS vectorstore, verifying HMAC first."""
    try:
        vpath = _vector_path(session_id)
        if not _verify_hmac(vpath):
            raise RuntimeError(
                f"Vectorstore integrity check failed for session {session_id}. "
                "Files may have been tampered with."
            )
        return FAISS.load_local(
            vpath,
            get_embedder(),
            allow_dangerous_deserialization=True,
        )
    except Exception as exc:
        print(f"Error loading vectorstore: {exc}")
        raise


# ── Knowledge Base vectorstore ──────────────────────────────────────

_KB_DIR_NAME = "_knowledge_base"
_kb_lock = threading.Lock()
_kb_vs_cache = None


def _kb_path() -> str:
    return os.path.join(VECTOR_DIR, _KB_DIR_NAME)


def _invalidate_kb_cache() -> None:
    global _kb_vs_cache
    _kb_vs_cache = None


def _load_kb_vs():
    global _kb_vs_cache
    if _kb_vs_cache is not None:
        return _kb_vs_cache
    kbp = _kb_path()
    if not os.path.isdir(kbp) or not os.path.isfile(os.path.join(kbp, "index.faiss")):
        return None
    try:
        vs = FAISS.load_local(kbp, get_embedder(), allow_dangerous_deserialization=True)
        _kb_vs_cache = vs
        return vs
    except Exception as exc:
        print(f"[WARN] KB load failed: {exc}")
        return None


def knowledge_base_exists() -> bool:
    kbp = _kb_path()
    return os.path.isdir(kbp) and os.path.isfile(os.path.join(kbp, "index.faiss"))


def verify_kb_on_startup() -> bool:
    """Verify KB integrity and warm the cache on application start."""
    kbp = _kb_path()
    if not os.path.isdir(kbp) or not os.path.isfile(os.path.join(kbp, "index.faiss")):
        return True
    if not _verify_hmac(kbp):
        print("[STARTUP] KB FAISS integrity check FAILED -- index may be corrupted")
        return False
    try:
        vs = FAISS.load_local(kbp, get_embedder(), allow_dangerous_deserialization=True)
        global _kb_vs_cache
        _kb_vs_cache = vs
        print("[STARTUP] KB FAISS integrity check passed, cached in memory")
        return True
    except Exception as exc:
        print(f"[STARTUP] KB FAISS load failed: {exc}")
        return False


def add_to_knowledge_base(
    text: str,
    report_id: str,
    source_type: str = "llm_analysis",
) -> int:
    """Chunk text and merge into the global Knowledge Base vectorstore.

    Args:
        text: The text content to index.
        report_id: Unique identifier for the source report.
        source_type: Provenance tag for RAG contamination guard.
            "llm_analysis" -- LLM-generated report (default).
            "primary_source" -- raw OSINT data.
            "uploaded_document" -- user-uploaded document.

    Returns the number of chunks added.
    """
    if not text or not text.strip():
        return 0

    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=150)
    prefixed = f"[report:{report_id[:8]}] {text}"
    chunks = splitter.split_text(prefixed)
    if not chunks:
        return 0

    # Attach provenance metadata to every chunk for RAG contamination guard
    metadatas = [
        {"source_type": source_type, "report_id": report_id[:8]}
        for _ in chunks
    ]

    with _kb_lock:
        kbp = _kb_path()
        embedder = get_embedder()
        new_vs = FAISS.from_texts(chunks, embedder, metadatas=metadatas)

        if knowledge_base_exists():
            try:
                existing = _load_kb_vs()
                if existing is None:
                    if not _verify_hmac(kbp):
                        print("[WARN] KB integrity check failed, rebuilding")
                        new_vs.save_local(kbp)
                        _write_hmac(kbp)
                        _invalidate_kb_cache()
                        return len(chunks)
                    existing = FAISS.load_local(
                        kbp, embedder, allow_dangerous_deserialization=True
                    )
                existing.merge_from(new_vs)
                existing.save_local(kbp)
                _write_hmac(kbp)
                _invalidate_kb_cache()
            except Exception as exc:
                print(f"[WARN] KB merge failed, overwriting: {exc}")
                new_vs.save_local(kbp)
                _write_hmac(kbp)
                _invalidate_kb_cache()
        else:
            os.makedirs(kbp, exist_ok=True)
            new_vs.save_local(kbp)
            _write_hmac(kbp)
            _invalidate_kb_cache()

    return len(chunks)


_MIN_COSINE_SIMILARITY = 0.3
"""Minimum cosine similarity for a KB chunk to be considered relevant.

With BGE normalized embeddings the FAISS L2^2 score relates to cosine
similarity via: cos_sim = 1 - score / 2.  We convert and filter so that
low-relevance chunks never pollute the LLM context.
"""


def query_knowledge_base(
    query: str,
    k: int = 3,
    filter_llm_content: bool = False,
) -> list[dict]:
    """Retrieve the top-k most relevant KB chunks for a query.

    The BGE query instruction prefix is applied automatically by the
    embedder so the model can distinguish queries from passages.

    Args:
        query: The search query.
        k: Maximum number of results.
        filter_llm_content: When True, exclude chunks tagged as
            ``source_type: "llm_analysis"`` entirely.  When False
            (default, for backward compatibility), LLM-generated chunks
            are still returned but their content is prefixed with
            ``[PRIOR ANALYSIS - not a primary source]`` so the LLM
            understands they are derived, not primary evidence.

    Returns:
        A list of dicts, each with keys ``content`` (str),
        ``source_type`` (str), and ``score`` (float, cosine similarity).
    """
    try:
        vs = _load_kb_vs()
        if vs is None:
            return []

        # Fetch extra candidates so we still have enough after filtering
        fetch_k = k * 3 if filter_llm_content else k
        docs_and_scores = vs.similarity_search_with_score(query, k=fetch_k)

        results: list[dict] = []
        for doc, l2_sq_score in docs_and_scores:
            # Convert FAISS L2^2 distance to cosine similarity
            # (valid for unit-normalised embeddings)
            cosine_sim = 1.0 - l2_sq_score / 2.0

            if cosine_sim < _MIN_COSINE_SIMILARITY:
                continue

            source_type = doc.metadata.get("source_type", "unknown") if doc.metadata else "unknown"

            if filter_llm_content and source_type == "llm_analysis":
                continue

            content = doc.page_content
            # Label LLM-generated content so downstream prompts treat it
            # as secondary reference, not primary evidence.
            if not filter_llm_content and source_type == "llm_analysis":
                content = "[PRIOR ANALYSIS - not a primary source] " + content

            results.append({
                "content": content,
                "source_type": source_type,
                "score": round(cosine_sim, 4),
            })

            if len(results) >= k:
                break

        return results
    except Exception as exc:
        print(f"[WARN] KB query failed: {exc}")
        _invalidate_kb_cache()
        return []


def rebuild_knowledge_base(reports: list) -> int:
    """Rebuild the entire KB from a list of report tuples.

    Accepts either ``(report_id, text)`` pairs (legacy) or
    ``(report_id, text, source_type)`` triples.  When *source_type* is
    omitted it defaults to ``"llm_analysis"``.

    Replaces the existing KB wholesale. Returns total chunks indexed.
    """
    if not reports:
        kbp = _kb_path()
        if os.path.isdir(kbp):
            import shutil
            shutil.rmtree(kbp)
        _invalidate_kb_cache()
        return 0

    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=150)
    all_chunks: list[str] = []
    all_metadatas: list[dict] = []
    for item in reports:
        report_id = item[0]
        text = item[1]
        source_type = item[2] if len(item) >= 3 else "llm_analysis"
        if text and text.strip():
            prefixed = f"[report:{report_id[:8]}] {text}"
            chunks = splitter.split_text(prefixed)
            all_chunks.extend(chunks)
            all_metadatas.extend(
                {"source_type": source_type, "report_id": report_id[:8]}
                for _ in chunks
            )

    if not all_chunks:
        return 0

    with _kb_lock:
        kbp = _kb_path()
        os.makedirs(kbp, exist_ok=True)
        vs = FAISS.from_texts(all_chunks, get_embedder(), metadatas=all_metadatas)
        vs.save_local(kbp)
        _write_hmac(kbp)
        _invalidate_kb_cache()

    return len(all_chunks)

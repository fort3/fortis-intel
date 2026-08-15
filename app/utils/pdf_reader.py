"""PDF text extraction with 3-tier fallback (PyMuPDF, pypdf, EasyOCR)."""

import io
import os
import tempfile

import pymupdf as fitz
from PIL import Image
from pypdf import PdfReader


_MAX_PDF_PAGES = 200


def extract_pdf_text(path):
    """Extract text from PDF file with multiple fallback methods.

    Uses a 3-tier extraction strategy:
      1. PyMuPDF (fitz) -- fastest, handles most PDFs
      2. pypdf -- fallback for PDFs that PyMuPDF struggles with
      3. EasyOCR -- last resort for scanned / image-based PDFs

    Args:
        path: Filesystem path to the PDF file.

    Returns:
        Extracted text as a single string.

    Raises:
        ValueError: If the PDF exceeds the page limit or contains no
            readable text after all methods are exhausted.
    """
    try:
        # ── Method 1: PyMuPDF ──────────────────────────────────────
        print("  [Method 1] Trying PyMuPDF extraction...")
        text_content = []
        try:
            doc = fitz.open(path)
            if len(doc) > _MAX_PDF_PAGES:
                doc.close()
                raise ValueError(f"PDF has {len(doc)} pages (max {_MAX_PDF_PAGES})")
            print(f"  PDF Pages Found: {len(doc)}")

            for page_num, page in enumerate(doc):
                page_text = page.get_text()
                if page_text.strip():
                    text_content.append(page_text)
                    print(f"    Page {page_num + 1}: {len(page_text)} chars extracted")
                else:
                    print(f"    Page {page_num + 1}: No text (might be image-based)")

            doc.close()

            full_text = "\n".join(text_content)
            if full_text.strip():
                print(f"  [OK] [Method 1] Success: {len(full_text)} chars extracted")
                return full_text
        except Exception as exc:
            print(f"  [ERROR] [Method 1] Failed: {exc}")

        # ── Method 2: pypdf ───────────────────────────────────────
        print("  [Method 2] Trying pypdf extraction...")
        try:
            reader = PdfReader(path)
            print(f"  PDF Pages Found: {len(reader.pages)}")

            text_content = []
            for i, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    text_content.append(page_text)
                    print(f"    Page {i + 1}: {len(page_text)} chars extracted")
                else:
                    print(f"    Page {i + 1}: No text extracted")

            full_text = "\n".join(text_content)
            if full_text.strip():
                print(f"  [OK] [Method 2] Success: {len(full_text)} chars extracted")
                return full_text
        except Exception as exc:
            print(f"  [ERROR] [Method 2] Failed: {exc}")

        # ── Method 3: EasyOCR ─────────────────────────────────────
        print("  [Method 3] Trying EasyOCR extraction...")
        try:
            import easyocr

            print("    Initializing OCR reader (downloading models on first run)...")
            reader = easyocr.Reader(["en"], gpu=False)

            ocr_text = []
            doc = fitz.open(path)

            for page_num, page in enumerate(doc):
                pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
                img_data = pix.tobytes("ppm")
                img = Image.open(io.BytesIO(img_data))

                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                    img.save(tmp.name)
                    temp_path = tmp.name

                try:
                    results = reader.readtext(temp_path)
                    page_text = "\n".join([text[1] for text in results])
                    if page_text.strip():
                        ocr_text.append(page_text)
                        print(f"    Page {page_num + 1} [OCR]: {len(page_text)} chars extracted")
                finally:
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass

            doc.close()

            full_text = "\n".join(ocr_text)
            if full_text.strip():
                print(f"  [OK] [Method 3] Success: {len(full_text)} chars extracted via OCR")
                return full_text
        except ImportError:
            print("  [INFO] [Method 3] Skipped: easyocr not installed")
        except Exception as exc:
            print(f"  [ERROR] [Method 3] Failed: {exc}")

        print("  [WARNING] No readable text found in PDF!")
        raise ValueError(
            "PDF is empty or unreadable. It may be encrypted, scanned without OCR, or corrupted."
        )

    except Exception as exc:
        print(f"  [ERROR] Error extracting PDF: {exc}")
        raise

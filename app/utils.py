from docx import Document
import io

def extract_document_text(file_bytes: bytes, filename: str) -> str:
    """Extract plain text for building the actual LLM prompt on a SAFE
    result. Deliberately separate from is_document_sensitive()'s internal
    extraction, since that function only returns True/False, not text."""
    if filename.endswith(".docx"):
        doc = Document(io.BytesIO(file_bytes))
        return "\n".join(p.text for p in doc.paragraphs)
    return file_bytes.decode("utf-8", errors="ignore")

MAX_DOCUMENT_CHARS = 20000  # conservative, stays well under the 8000 TPM cap

def truncate_document_text(document_text: str) -> str:
    if len(document_text) > MAX_DOCUMENT_CHARS:
        print(f"WARNING: Document truncated from {len(document_text)} to {MAX_DOCUMENT_CHARS} characters")
        return document_text[:MAX_DOCUMENT_CHARS]
    return document_text
import io
import pandas as pd
from dotenv import load_dotenv
from docx import Document
from oletools.olevba import VBA_Parser
from app.config import SECURITY_PROMPT, search_list, phrase_list
import fitz  # PyMuPDF

## String search (looking for key words to raise flags) ##
def find_string_in_file(document_text, search_list):
    for line in document_text.splitlines():
        if any(search_string in line for search_string in search_list):
            return "sensitive"
    return "non-sensitive"

def has_pdf_javascript(pdf_document):
    for obj_num in range(1, pdf_document.xref_length()):
        try:
            obj_str = pdf_document.xref_object(obj_num)
            if "/JavaScript" in obj_str or "/JS" in obj_str:
                return True
        except Exception:
            continue
    return False

def llm_classify_document(document_text, search_list, phrase_list):
    """One call covering phrase/pattern/hidden-content/embedded-code checks
    (previously four separate LLM calls — consolidated in Session 5)."""
    # Import lazily so this module can be loaded while app.main is being
    # initialized, without creating a circular import at startup.
    from app.main import client

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[
            {"role": "system", "content": SECURITY_PROMPT},
            {"role": "user", "content": (
                f"Flagged keywords to check for: {search_list}\n"
                f"Flagged phrases/patterns to check for: {phrase_list}\n\n"
                f"Document:\n{document_text}"
            )},
        ],
    )
    reply = response.choices[0].message.content.strip().upper()
    return reply == "FLAGGED"

def is_prompt_flagged(user_prompt: str) -> bool:
    """Shared flag-check for text-only prompts. Used identically by /chat
    and /admin/chat — pulled out to avoid keeping two copies in sync."""
    return (
        find_string_in_file(user_prompt, search_list) == "sensitive"
        or llm_classify_document(user_prompt, search_list, phrase_list)
    )

def is_document_sensitive(document_text, filetype=None):
    if filetype == "application/pdf":
        pdf_document = fitz.open(stream=document_text, filetype="pdf")
        if has_pdf_javascript(pdf_document):
            print("WARNING: JavaScript detected — quarantining file")
            return True
        elif pdf_document.is_encrypted:
            print("WARNING: Encrypted PDF detected — quarantining file")
            return True
        # is_restricted removed — confirmed not to exist on this Document object
        document_text = ""
        for page in pdf_document:
            document_text += page.get_text()

    elif filetype == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        doc = Document(io.BytesIO(document_text))
        body_text = "\n".join(p.text for p in doc.paragraphs)

        metadata_text = "\n".join(filter(None, [
            doc.core_properties.author,
            doc.core_properties.subject,
            doc.core_properties.comments,
            doc.core_properties.keywords,
            doc.core_properties.last_modified_by,
            doc.core_properties.title,
            doc.core_properties.category,
            doc.core_properties.content_status,
            doc.core_properties.identifier,
        ]))

        # Concatenate so both get scanned — but keep them labeled, since
        # "injection found in metadata" vs "in body" is a genuinely useful
        # distinction to log separately for your README's findings section
        document_text = f"[BODY TEXT]\n{body_text}\n\n[METADATA]\n{metadata_text}"

    elif filetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
        df = pd.read_excel(io.BytesIO(document_text))
        document_text = df.to_string()

    elif filetype in ["application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint"]:
        vba_parser = VBA_Parser(filename="uploaded_file", data=document_text)
        if vba_parser.detect_vba_macros():
            print("WARNING: Macros detected — quarantining file")
            return True
        document_text = ""
        for (_, _, _, vba_code) in vba_parser.extract_macros():
            document_text += vba_code + "\n"

    else:
        # Fixed: plain text / unrecognized types previously crashed here with a TypeError since document_text was still raw bytes.
        if isinstance(document_text, bytes):
            document_text = document_text.decode("utf-8", errors="ignore")

    # Fast, cheap check first — no API call needed
    if find_string_in_file(document_text, search_list) == "sensitive":
        return True

    # Single consolidated LLM call replaces the previous four
    return llm_classify_document(document_text, search_list, phrase_list)

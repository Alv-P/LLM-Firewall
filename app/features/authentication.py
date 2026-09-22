from fastapi import Header, HTTPException
import secrets
import os

ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "changeme-dev-key")

# Admin authentication function to seperate admin/testing endpoints from public-facing endpoints
def require_admin(x_admin_key: str = Header(None)):
    """
    Minimal header-based gate separating admin/testing endpoints from the
    public-facing surface. This is intentionally simple for a hackathon
    build — a production deployment would use proper OAuth/JWT-based auth
    with per-organization API keys, not a single shared secret. Documented
    explicitly as a known limitation, not presented as production-ready.
    """
    if not x_admin_key or not secrets.compare_digest(x_admin_key, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Admin access required.")
    return True
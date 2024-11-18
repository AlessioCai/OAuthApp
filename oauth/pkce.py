import os
import hashlib
import base64

def generate_pkce():
    """Genera il code_verifier e il code_challenge per PKCE."""
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("utf-8")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("utf-8")).digest()
    ).rstrip(b"=").decode("utf-8")
    return code_challenge, code_verifier
    
import os
import json
import time
from cryptography.fernet import Fernet

TOKEN_FILE = "tokens.enc"
KEY_FILE = "secret.key"

def generate_key():
    """Genera una chiave crittografica se non esiste già."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)

def load_key():
    """Carica la chiave crittografica."""
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("Chiave non trovata! Generala con generate_key().")
    with open(KEY_FILE, "rb") as f:
        return f.read()

def save_tokens(tokens):
    """Cifra e salva i token, includendo il tempo di scadenza."""
    generate_key()  # Assicurati che la chiave esista
    key = load_key()
    fernet = Fernet(key)

    # Calcoliamo il tempo di scadenza (se fornito)
    expires_in = tokens.get("expires_in", 3600)  # Default: 1 ora
    tokens["expires_at"] = int(time.time()) + expires_in

    encrypted_data = fernet.encrypt(json.dumps(tokens).encode("utf-8"))
    with open(TOKEN_FILE, "wb") as f:
        f.write(encrypted_data)



def load_tokens():
    """Carica e decifra i token salvati."""
    if not os.path.exists(TOKEN_FILE):
        return None
    key = load_key()
    fernet = Fernet(key)
    with open(TOKEN_FILE, "rb") as f:
        encrypted_data = f.read()
    return json.loads(fernet.decrypt(encrypted_data).decode("utf-8"))

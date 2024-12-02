import os
import json
import time
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Carica variabili d'ambiente dal file .env
load_dotenv()

TOKEN_FILE = "tokens.enc"

def generate_key():
    """Genera una chiave crittografica se non esiste già."""
    key = Fernet.generate_key()
    print("ATTENZIONE: Chiave generata. Salvala in modo sicuro!")
    print(f"Chiave: {key.decode('utf-8')}")
    return key

def load_key():
    """Carica la chiave crittografica dalle variabili d'ambiente."""
    key = os.getenv("SECRET_KEY")
    if not key:
        raise ValueError(
            "Chiave crittografica non trovata! Assicurati che la variabile d'ambiente 'SECRET_KEY' sia configurata."
        )
    return key.encode("utf-8")

def save_tokens(tokens):
    """Cifra e salva i token."""
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

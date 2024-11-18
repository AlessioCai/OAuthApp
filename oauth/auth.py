import webbrowser
import requests
from flask import Flask, request
from threading import Timer
from oauth.pkce import generate_pkce
from oauth.tokens import save_tokens, load_tokens

# Configurazione
CLIENT_ID = "399182003500-mpc10pdcanknlsojas0ugvqng2httup0.apps.googleusercontent.com"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REDIRECT_URI = "http://127.0.0.1:8080/callback"
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"]

# Flask app per gestire il callback
app = Flask(__name__)

@app.route("/callback")
def callback():
    """Gestisce il redirect e scambia il codice per i token."""
    auth_code = request.args.get("code")
    if not auth_code:
        return "Errore: Nessun codice di autorizzazione ricevuto.", 400
    
    # Passa il code_verifier insieme al codice di autorizzazione
    tokens = exchange_code_for_token(auth_code, code_verifier)
    return "Autenticazione completata con successo!", 200


def build_authorization_url():
    """Crea l'URL di autorizzazione usando PKCE."""
    code_challenge, code_verifier = generate_pkce()
    url = (
        f"{AUTH_URL}?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope={' '.join(SCOPES)}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    return url, code_verifier


def exchange_code_for_token(auth_code, code_verifier):
    """Scambia il codice di autorizzazione per i token."""
    data = {
        "code": auth_code,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    }
    response = requests.post(TOKEN_URL, data=data)
    if response.status_code == 200:
        tokens = response.json()
        save_tokens(tokens)
        return tokens
    return {"error": "Errore durante lo scambio del codice."}

def start_auth_flow():
    """Avvia il flusso di autenticazione."""
    url, code_verifier = build_authorization_url()
    Timer(1, webbrowser.open, args=(url,)).start()
    app.run(port=8080, debug=False)
    return code_verifier  # Restituisce il code_verifier per usarlo nel callback


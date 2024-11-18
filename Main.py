import os
import base64
import hashlib
import requests
from flask import Flask, request, jsonify
import webbrowser
from threading import Timer

# Configurazione
CLIENT_ID = "399182003500-mpc10pdcanknlsojas0ugvqng2httup0.apps.googleusercontent.com"  
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REDIRECT_URI = "http://127.0.0.1:8080/callback"
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"]

# Variabili globali per PKCE
code_verifier = None
state = None

# Flask per ricevere il codice di autorizzazione
app = Flask(__name__)

@app.route("/callback")
def callback():
    """Gestisce il redirect dal provider OAuth"""
    auth_code = request.args.get("code")
    error = request.args.get("error")
    if error:
        return f"Errore durante l'autenticazione: {error}", 400
    if auth_code:
        # Chiama una funzione per scambiare il codice con un token
        token_data = exchange_code_for_token(auth_code)
        return jsonify(token_data)
    return "Nessun codice ricevuto", 400

def generate_pkce():
    """Genera il codice verificatore e il challenge per PKCE"""
    global code_verifier
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("utf-8")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("utf-8")).digest()
    ).rstrip(b"=").decode("utf-8")
    return code_challenge

def build_authorization_url():
    """Costruisce l'URL per l'autorizzazione"""
    code_challenge = generate_pkce()
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "redirect_uri": REDIRECT_URI,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "offline"
    }
    url = f"{AUTH_URL}?{requests.utils.urlencode(params)}"
    return url

def exchange_code_for_token(auth_code):
    """Scambia il codice di autorizzazione con un token di accesso"""
    data = {
        "code": auth_code,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    }
    response = requests.post(TOKEN_URL, data=data)
    if response.status_code == 200:
        return response.json()  # Token di accesso e refresh
    return {"error": "Failed to obtain token", "details": response.json()}

def open_browser(url):
    """Apre il browser predefinito per l'utente"""
    webbrowser.open(url)

def start_local_server():
    """Avvia un server locale per catturare il redirect"""
    Timer(1, open_browser, args=(build_authorization_url(),)).start()
    app.run(port=8080, debug=False)

if __name__ == "__main__":
    print("Avvio del processo di autenticazione OAuth 2.0 con PKCE...")
    start_local_server()

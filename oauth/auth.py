import time
import webbrowser
import requests
from flask import Flask, request, session, redirect, url_for
from oauth.pkce import generate_pkce
from oauth.tokens import load_tokens, save_tokens
from dotenv import load_dotenv
import os

load_dotenv()

# Configurazione tramite .env
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"]


# Percorso del file della whitelist
WHITELIST_FILE = "whitelist.txt"

def load_whitelist():
    """Carica la whitelist di email da un file."""
    if not os.path.exists(WHITELIST_FILE):
        raise FileNotFoundError(f"File whitelist non trovato: {WHITELIST_FILE}")
    with open(WHITELIST_FILE, "r") as f:
        # Restituisce un set di email autorizzate
        return {line.strip() for line in f if line.strip()}

# Carica la whitelist all'avvio dell'app
try:
    WHITELIST_EMAILS = load_whitelist()
except FileNotFoundError as e:
    print(e)
    WHITELIST_EMAILS = set()

# Flask app per gestire il callback
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")  # Chiave per sessione Flask (da .env)


@app.route('/login', methods=['GET'])
def login():
    """Inizia il flusso di autenticazione."""
    # Genera il code_verifier e il code_challenge
    code_challenge, code_verifier = generate_pkce()
    session['code_verifier'] = code_verifier  # Salva il code_verifier nella sessione

    # Costruisci l'URL di autorizzazione
    url = (
        f"{AUTH_URL}?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope={' '.join(SCOPES)}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    return redirect(url)


@app.route('/callback', methods=['GET'])
def callback():
    """Gestisce il redirect e scambia il codice per i token."""
    auth_code = request.args.get("code")
    if not auth_code:
        return "Errore: Nessun codice di autorizzazione ricevuto.", 400

    # Recupera il code_verifier dalla sessione
    code_verifier = session.get('code_verifier')
    if not code_verifier:
        return "Errore: code_verifier non trovato nella sessione.", 400

    # Scambia il codice di autorizzazione per i token
    data = {
        "code": auth_code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    }
    response = requests.post(TOKEN_URL, data=data)
    if response.status_code != 200:
        return f"Errore durante lo scambio del codice: {response.json()}", 400

    tokens = response.json()
    access_token = tokens.get("access_token")

    # Recupera i dati del profilo utente
    userinfo_response = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if userinfo_response.status_code != 200:
        return f"Errore nel recupero delle informazioni utente: {userinfo_response.json()}", 400

    userinfo = userinfo_response.json()
    user_email = userinfo.get("email")

    # Verifica se l'email è nella whitelist
    if user_email not in WHITELIST_EMAILS:
        return "Accesso negato: l'email non è autorizzata.", 403

    # Salva i token se l'email è autorizzata
    save_tokens(tokens)
    return f"Autenticazione completata per {user_email}.", 200


@app.route('/')
def index():
    """Pagina iniziale, verifica se l'utente è autenticato."""
    if 'access_token' not in session:
        return redirect(url_for('login'))
    return "Sei autenticato correttamente!"


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
    """Avvia il server Flask per gestire il flusso di autenticazione."""
    webbrowser.open("http://127.0.0.1:8080/login")
    app.run(port=8080, debug=False)


def refresh_access_token(tokens):
    """Rinnova l'access_token utilizzando il refresh_token."""
    if "refresh_token" not in tokens:
        raise ValueError("refresh_token non trovato. È necessario autenticarsi di nuovo.")

    data = {
        "client_id": CLIENT_ID,
        "client_secret": 'da gestire, non permette di pusharlo, usare variabile env',
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
    }
    
    response = requests.post(TOKEN_URL, data=data)
    
    if response.status_code != 200:
        raise Exception(f"Errore nel rinnovo del token: {response.json()}")

    new_tokens = response.json()
    # Manteniamo il refresh_token originale se non viene restituito
    new_tokens["refresh_token"] = new_tokens.get("refresh_token", tokens["refresh_token"])
    save_tokens(new_tokens)
    return new_tokens


def get_valid_tokens():
    """Verifica se l'access_token è valido e lo rinnova se necessario."""
    tokens = load_tokens()
    if not tokens:
        return None

    # Controlliamo se il token è scaduto
    expires_at = tokens.get("expires_at", 0)
    if time.time() > expires_at:
        print("Token scaduto, rinnovo in corso...")
        tokens = refresh_access_token(tokens)
    else:
        print("Token valido trovato.")

    return tokens

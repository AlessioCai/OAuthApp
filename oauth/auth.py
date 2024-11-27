import webbrowser
import requests
from flask import Flask, request, session, redirect, url_for
from oauth.pkce import generate_pkce
from oauth.tokens import save_tokens

# Configurazione
CLIENT_ID = "399182003500-mpc10pdcanknlsojas0ugvqng2httup0.apps.googleusercontent.com"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REDIRECT_URI = "http://127.0.0.1:8080/callback"
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"]

# Flask app per gestire il callback
app = Flask(__name__)
app.secret_key = "3d6f45adffefschjkc12445ddejdkei59c3b6c7cb1"  # Necessario per sessioni Flask


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
    tokens = exchange_code_for_token(auth_code, code_verifier)
    session['access_token'] = tokens.get('access_token')
    session['refresh_token'] = tokens.get('refresh_token')

    return redirect(url_for('index'))


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

from oauth.auth import start_auth_flow
from oauth.tokens import load_tokens

def main():
    tokens = load_tokens()
    if tokens:
        print("Token trovati:")
        print(tokens)
    else:
        print("Nessun token trovato. Avvio dell'autenticazione...")
        code_verifier = start_auth_flow()
        print("Flusso di autenticazione completato.")

if __name__ == "__main__":
    main()

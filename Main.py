from oauth.auth import start_auth_flow, get_valid_tokens

def main():
    tokens = get_valid_tokens()
    if tokens:
        print("Token validi trovati:")
        print(tokens)
    else:
        print("Nessun token valido trovato. Avvio dell'autenticazione...")
        start_auth_flow()
        print("Flusso di autenticazione completato.")

if __name__ == "__main__":
    main()

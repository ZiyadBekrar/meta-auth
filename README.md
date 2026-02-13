# TokenMeta

## Meta token generation route

This project exposes a route:

- `GET /meta-auth`: redirects the user to Meta (Facebook) OAuth
- `GET /meta-auth/callback`: exchanges the returned `code` for a long-lived Meta token and stores it in Google Secret Manager (no token is displayed)

## Setup

1. Create a Meta app and configure **Valid OAuth Redirect URIs** to include:
   - `http://localhost:8000/meta-auth/callback`

2. Create your env file:

```bash
cp .env.example .env
```

3. Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

4. Run the server:

```bash
uvicorn main:app --reload
```

Then open:
- `http://localhost:8000/meta-auth`

## Google Secret Manager auth (local)

This app uses a **service account JSON** to write to Secret Manager.

- Set `GCP_SERVICE_ACCOUNT_FILE` (default is `./credentials.json`)
- Ensure the service account has permission to `accessSecretVersion` and `addSecretVersion` on the target secret.



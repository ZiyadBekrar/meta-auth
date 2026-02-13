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

## Deploy to Cloud Run

1. Build and deploy:

```bash
gcloud run deploy tokenmeta \
  --source . \
  --region YOUR_REGION \
  --allow-unauthenticated
```

2. Set environment variables on the service (at least):

- `META_REDIRECT_URI` (must match the Cloud Run URL + `/meta-auth/callback`)

`META_APP_ID` and `META_APP_SECRET` are read directly from Google Secret Manager at runtime:

- `projects/358205627399/secrets/META_APP_ID/versions/latest`
- `projects/358205627399/secrets/META_APP_SECRET/versions/latest`

3. Secret Manager permissions (Cloud Run)

In Cloud Run, **do not ship `credentials.json`**. Instead, attach a Cloud Run service account that has:

- `secretmanager.versions.access`
- `secretmanager.versions.add`

The app will use **Application Default Credentials** automatically when `GCP_SERVICE_ACCOUNT_FILE` is not set.



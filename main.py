import os
import secrets
import base64
import hashlib
import hmac
import time
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

def _load_dotenv_file(path: str = ".env") -> None:
    """
    Minimal .env loader to avoid requiring python-dotenv.
    - Ignores blank lines and comments
    - Supports KEY=VALUE (optionally quoted)
    - Does not override existing environment variables
    """

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if not key:
                    continue
                os.environ.setdefault(key, value)
    except FileNotFoundError:
        return


_load_dotenv_file()

META_API_VERSION = "v24.0"
META_APP_ID = os.getenv("META_APP_ID")
META_APP_SECRET = os.getenv("META_APP_SECRET")
META_REDIRECT_URI = os.getenv(
    "META_REDIRECT_URI", "http://localhost:8000/meta-auth/callback"
)
META_SCOPES = "business_management"

app = FastAPI()

_STATE_TTL_SECONDS = 600
GSM_SECRET_VERSION = "projects/358205627399/secrets/META_TEST/versions/latest"
GCP_SERVICE_ACCOUNT_FILE = "/Users/stratimpulse1/Documents/tokenmeta/credentials.json"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def _make_signed_state() -> str:
    """
    Create a signed OAuth state value.
    This avoids relying on browser cookies being preserved across redirects.
    """
    if not META_APP_SECRET:
        # META_APP_SECRET is also our signing key; missing config is handled elsewhere.
        return secrets.token_urlsafe(32)

    issued_at = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
    payload = f"{issued_at}.{nonce}".encode("utf-8")

    sig = hmac.new(
        META_APP_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).digest()

    return f"{_b64url_encode(payload)}.{_b64url_encode(sig)}"


def _verify_signed_state(state: str) -> bool:
    if not META_APP_SECRET:
        return False
    try:
        payload_b64, sig_b64 = state.split(".", 1)
        payload = _b64url_decode(payload_b64)
        sig = _b64url_decode(sig_b64)
        expected = hmac.new(
            META_APP_SECRET.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(sig, expected):
            return False

        issued_at_str, _nonce = payload.decode("utf-8").split(".", 1)
        issued_at = int(issued_at_str)
        return (time.time() - issued_at) <= _STATE_TTL_SECONDS
    except Exception:
        return False


def _secret_parent_from_version_name(version_name: str) -> str:
    if "/versions/" in version_name:
        return version_name.split("/versions/", 1)[0]
    return version_name


def _upload_to_google_secret_manager_if_changed(token: str) -> tuple[bool, str]:
    """
    Stores `token` in Google Secret Manager if it differs from the current latest value.

    Returns (updated, message).
    """
    try:
        from google.cloud import secretmanager  # type: ignore
    except Exception:
        return (
            False,
            "Google Secret Manager library is not installed. Run: python -m pip install google-cloud-secret-manager",
        )

    if not token:
        return (False, "No token to upload.")

    # Prefer explicit service account file (local/dev) when provided.
    try:
        from google.oauth2 import service_account  # type: ignore
    except Exception:
        service_account = None  # type: ignore

    creds = None
    if GCP_SERVICE_ACCOUNT_FILE:
        if not os.path.exists(GCP_SERVICE_ACCOUNT_FILE):
            return (
                False,
                f"Service account file not found at {GCP_SERVICE_ACCOUNT_FILE}",
            )
        if service_account is None:
            return (
                False,
                "google-auth is missing service account support (unexpected). Reinstall google-cloud-secret-manager.",
            )
        try:
            creds = service_account.Credentials.from_service_account_file(
                GCP_SERVICE_ACCOUNT_FILE
            )
        except Exception as e:
            return (False, f"Failed to load service account credentials: {type(e).__name__}")

    client = (
        secretmanager.SecretManagerServiceClient(credentials=creds)
        if creds is not None
        else secretmanager.SecretManagerServiceClient()
    )

    current_value: Optional[str] = None
    try:
        current = client.access_secret_version(name=GSM_SECRET_VERSION)
        current_value = current.payload.data.decode("utf-8")
    except Exception:
        current_value = None

    if current_value is not None and current_value == token:
        return (False, "Token unchanged; secret not updated.")

    parent = _secret_parent_from_version_name(GSM_SECRET_VERSION)
    try:
        client.add_secret_version(
            parent=parent,
            payload={"data": token.encode("utf-8")},
        )
    except Exception as e:
        return (False, f"Failed to upload token to Secret Manager: {type(e).__name__}")

    return (True, "Token uploaded to Secret Manager successfully.")



def _missing_env_error_html(*names: str) -> HTMLResponse:
    missing = [n for n in names if not os.getenv(n)]
    return HTMLResponse(
        f"""
        <html>
          <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
            <h2>Missing configuration</h2>
            <p>Set these environment variables and restart the server:</p>
            <pre>{chr(10).join(missing)}</pre>
            <p>Tip: copy <code>.env.example</code> to <code>.env</code>.</p>
          </body>
        </html>
        """.strip(),
        status_code=500,
    )


@app.get("/", response_class=HTMLResponse)
async def home() -> HTMLResponse:
    return HTMLResponse(
        """
        <html>
          <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
            <h2>TokenMeta</h2>
            <p><a href="/meta-auth">Start Meta OAuth</a></p>
          </body>
        </html>
        """.strip()
    )


@app.get("/meta-auth")
async def meta_auth(request: Request):
    """
    Starts the Meta (Facebook) OAuth flow.
    The user will be taken to Meta and asked to authorize your app, returning an access token.
    """

    if not META_APP_ID:
        return _missing_env_error_html("META_APP_ID", "META_APP_SECRET")

    state = _make_signed_state()
    scopes = ",".join([s.strip() for s in META_SCOPES.split(",") if s.strip()])

    redirect_url = (
        f"https://www.facebook.com/{META_API_VERSION}/dialog/oauth"
        f"?client_id={META_APP_ID}"
        f"&redirect_uri={httpx.URL(META_REDIRECT_URI)}"
        f"&state={state}"
        f"&response_type=code"
        + (f"&scope={scopes}" if scopes else "")
    )

    resp = RedirectResponse(url=redirect_url, status_code=302)
    resp.set_cookie(
        "meta_oauth_state",
        state,
        max_age=600,
        path="/",
        httponly=True,
        samesite="lax",
        secure=(request.url.scheme == "https"),
    )
    return resp


@app.get("/meta-auth/callback", response_class=HTMLResponse)
async def meta_auth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
) -> HTMLResponse:
    """
    Handles Meta OAuth callback and exchanges `code` for an access token.
    """

    if not (META_APP_ID and META_APP_SECRET and META_REDIRECT_URI):
        return _missing_env_error_html("META_APP_ID", "META_APP_SECRET", "META_REDIRECT_URI")

    if error:
        return HTMLResponse(
            f"""
            <html>
              <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
                <h2>Meta authorization error</h2>
                <p><b>{error}</b></p>
                <pre>{(error_description or "").strip()}</pre>
                <p><a href="/meta-auth">Try again</a></p>
              </body>
            </html>
            """.strip(),
            status_code=400,
        )

    if not state or not _verify_signed_state(state):
        return HTMLResponse(
            """
            <html>
              <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
                <h2>Invalid state</h2>
                <p>The OAuth <code>state</code> value was missing, invalid, or expired. Please restart the flow.</p>
                <p><a href="/meta-auth">Start over</a></p>
              </body>
            </html>
            """.strip(),
            status_code=400,
        )

    if not code:
        return HTMLResponse(
            """
            <html>
              <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
                <h2>Missing code</h2>
                <p>Meta did not return an OAuth <code>code</code>.</p>
                <p><a href="/meta-auth">Start over</a></p>
              </body>
            </html>
            """.strip(),
            status_code=400,
        )

    token_url = f"https://graph.facebook.com/{META_API_VERSION}/oauth/access_token"
    code_exchange_params = {
        "client_id": META_APP_ID,
        "client_secret": META_APP_SECRET,
        "redirect_uri": META_REDIRECT_URI,
        "code": code,
    }

    async with httpx.AsyncClient(timeout=20) as client:
        # 1) Exchange code -> short-lived user access token
        r = await client.get(token_url, params=code_exchange_params)
        if r.status_code >= 400:
            try:
                details = r.json()
            except Exception:
                details = {"status_code": r.status_code, "body": r.text}
            return HTMLResponse(
                f"""
                <html>
                  <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
                    <h2>Code exchange failed</h2>
                    <pre>{details}</pre>
                    <p><a href="/meta-auth">Try again</a></p>
                  </body>
                </html>
                """.strip(),
                status_code=400,
            )

        short_data = r.json()
        short_access_token = short_data.get("access_token", "")
        if not short_access_token:
            return HTMLResponse(
                f"""
                <html>
                  <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
                    <h2>Code exchange returned no access token</h2>
                    <pre>{short_data}</pre>
                    <p><a href="/meta-auth">Try again</a></p>
                  </body>
                </html>
                """.strip(),
                status_code=400,
            )

        # 2) Exchange short-lived -> long-lived user access token
        long_lived_params = {
            "grant_type": "fb_exchange_token",
            "client_id": META_APP_ID,
            "client_secret": META_APP_SECRET,
            "fb_exchange_token": short_access_token,
        }
        r2 = await client.get(token_url, params=long_lived_params)
        if r2.status_code >= 400:
            try:
                details2 = r2.json()
            except Exception:
                details2 = {"status_code": r2.status_code, "body": r2.text}
            return HTMLResponse(
                f"""
                <html>
                  <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
                    <h2>Long-lived token exchange failed</h2>
                    <pre>{details2}</pre>
                    <p><a href="/meta-auth">Try again</a></p>
                  </body>
                </html>
                """.strip(),
                status_code=400,
            )

        long_data = r2.json()

    long_access_token = long_data.get("access_token", "")
    if not long_access_token:
        return HTMLResponse(
            """
            <html>
              <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
                <h2>Failed</h2>
                <p>Meta did not return a long-lived access token.</p>
                <p><a href="/meta-auth">Try again</a></p>
              </body>
            </html>
            """.strip(),
            status_code=400,
        )

    updated, message = _upload_to_google_secret_manager_if_changed(long_access_token)

    resp = HTMLResponse(
        f"""
        <html>
          <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
            <h2>{"Success" if updated else "Failed"}</h2>
            <p>{message}</p>
            <p><a href="/meta-auth">Generate another token</a></p>
          </body>
        </html>
        """.strip()
    )
    resp.delete_cookie("meta_oauth_state")
    return resp

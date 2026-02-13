import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional


def load_dotenv_file(path: str = ".env") -> None:
    """
    Minimal .env loader (no python-dotenv dependency).
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


@dataclass(frozen=True)
class Settings:
    meta_api_version: str
    meta_app_id: Optional[str]
    meta_app_secret: Optional[str]
    meta_redirect_uri: str
    meta_scopes: str

    state_ttl_seconds: int

    gsm_secret_version: str
    gcp_service_account_file: str

    @staticmethod
    def from_env() -> "Settings":
        return Settings(
            meta_api_version=os.getenv("META_API_VERSION", "v24.0"),
            meta_app_id=os.getenv("META_APP_ID"),
            meta_app_secret=os.getenv("META_APP_SECRET"),
            meta_redirect_uri=os.getenv(
                "META_REDIRECT_URI", "http://localhost:8000/meta-auth/callback"
            ),
            meta_scopes=os.getenv("META_SCOPES", "business_management"),
            state_ttl_seconds=int(os.getenv("STATE_TTL_SECONDS", "600")),
            gsm_secret_version=os.getenv(
                "GSM_SECRET_VERSION",
                "projects/358205627399/secrets/META_TEST/versions/latest",
            ),
            gcp_service_account_file=os.getenv(
                "GCP_SERVICE_ACCOUNT_FILE",
                "/Users/stratimpulse1/Documents/tokenmeta/credentials.json",
            ),
        )


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def make_signed_state(app_secret: str, ttl_seconds: int = 600) -> str:
    """
    Create a signed OAuth state value.
    Format: base64url(payload).base64url(hmac_sha256(payload))
    payload: "{issued_at}.{nonce}"
    """

    issued_at = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
    payload = f"{issued_at}.{nonce}".encode("utf-8")

    sig = hmac.new(
        app_secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).digest()

    # ttl_seconds is enforced in verify_signed_state; included here for API symmetry.
    _ = ttl_seconds
    return f"{_b64url_encode(payload)}.{_b64url_encode(sig)}"


def verify_signed_state(state: str, app_secret: str, ttl_seconds: int = 600) -> bool:
    try:
        payload_b64, sig_b64 = state.split(".", 1)
        payload = _b64url_decode(payload_b64)
        sig = _b64url_decode(sig_b64)
        expected = hmac.new(
            app_secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(sig, expected):
            return False

        issued_at_str, _nonce = payload.decode("utf-8").split(".", 1)
        issued_at = int(issued_at_str)
        return (time.time() - issued_at) <= ttl_seconds
    except Exception:
        return False


def build_meta_oauth_dialog_url(settings: Settings, state: str) -> str:
    # Import locally to keep helpers import-light.
    import httpx

    scopes = ",".join([s.strip() for s in settings.meta_scopes.split(",") if s.strip()])
    return (
        f"https://www.facebook.com/{settings.meta_api_version}/dialog/oauth"
        f"?client_id={settings.meta_app_id}"
        f"&redirect_uri={httpx.URL(settings.meta_redirect_uri)}"
        f"&state={state}"
        f"&response_type=code"
        + (f"&scope={scopes}" if scopes else "")
    )


async def exchange_code_for_long_lived_user_access_token(
    settings: Settings, *, code: str
) -> str:
    """
    code -> short-lived token -> long-lived token
    Returns the long-lived access token (string). Raises ValueError on failure.
    """

    import httpx

    if not settings.meta_app_id or not settings.meta_app_secret:
        raise ValueError("Missing META_APP_ID or META_APP_SECRET")

    token_url = f"https://graph.facebook.com/{settings.meta_api_version}/oauth/access_token"

    async with httpx.AsyncClient(timeout=20) as client:
        # 1) code -> short-lived user token
        r = await client.get(
            token_url,
            params={
                "client_id": settings.meta_app_id,
                "client_secret": settings.meta_app_secret,
                "redirect_uri": settings.meta_redirect_uri,
                "code": code,
            },
        )
        if r.status_code >= 400:
            raise ValueError(f"Code exchange failed: {r.text}")
        short_data = r.json()
        short_access_token = short_data.get("access_token", "")
        if not short_access_token:
            raise ValueError("Code exchange returned no access token")

        # 2) short-lived -> long-lived user token
        r2 = await client.get(
            token_url,
            params={
                "grant_type": "fb_exchange_token",
                "client_id": settings.meta_app_id,
                "client_secret": settings.meta_app_secret,
                "fb_exchange_token": short_access_token,
            },
        )
        if r2.status_code >= 400:
            raise ValueError(f"Long-lived exchange failed: {r2.text}")
        long_data = r2.json()
        long_access_token = long_data.get("access_token", "")
        if not long_access_token:
            raise ValueError("Long-lived exchange returned no access token")

    return long_access_token


def _secret_parent_from_version_name(version_name: str) -> str:
    # "projects/.../secrets/NAME/versions/latest" -> "projects/.../secrets/NAME"
    if "/versions/" in version_name:
        return version_name.split("/versions/", 1)[0]
    return version_name


def upload_to_google_secret_manager_if_changed(
    *,
    token: str,
    secret_version: str,
    service_account_file: str,
) -> tuple[bool, str]:
    """
    Stores `token` in Google Secret Manager if it differs from current `secret_version`.
    Returns (updated, message).
    """

    try:
        from google.cloud import secretmanager  # type: ignore
        from google.oauth2 import service_account  # type: ignore
    except Exception:
        return (
            False,
            "Missing Google Secret Manager dependencies. Install: google-cloud-secret-manager",
        )

    if not token:
        return (False, "No token to upload.")

    if not service_account_file or not os.path.exists(service_account_file):
        return (False, f"Service account file not found at {service_account_file}")

    try:
        creds = service_account.Credentials.from_service_account_file(service_account_file)
    except Exception as e:
        return (False, f"Failed to load service account credentials: {type(e).__name__}")

    client = secretmanager.SecretManagerServiceClient(credentials=creds)

    current_value: Optional[str] = None
    try:
        current = client.access_secret_version(name=secret_version)
        current_value = current.payload.data.decode("utf-8")
    except Exception:
        current_value = None

    if current_value is not None and current_value == token:
        return (False, "Token unchanged; secret not updated.")

    parent = _secret_parent_from_version_name(secret_version)
    try:
        client.add_secret_version(parent=parent, payload={"data": token.encode("utf-8")})
    except Exception as e:
        return (False, f"Failed to upload token to Secret Manager: {type(e).__name__}")

    return (True, "Token uploaded to Secret Manager successfully.")


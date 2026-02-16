import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional, Set, Tuple
 
import httpx
from google.api_core import exceptions as gcp_exceptions
from google.cloud import secretmanager
from google.oauth2 import service_account
 
 
META_APP_ID_SECRET_RESOURCE = "projects/358205627399/secrets/META_APP_ID"
META_APP_SECRET_SECRET_RESOURCE = "projects/358205627399/secrets/META_APP_SECRET"
META_REDIRECT_URI_SECRET_RESOURCE = "projects/358205627399/secrets/META_REDIRECT_URI"
 
 
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")
 
 
def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("utf-8"))
 
 
def load_dotenv_file(path: str = ".env") -> None:
    """
    Minimal .env loader for local dev.
 
    IMPORTANT: explicitly ignores META_APP_ID / META_APP_SECRET so they are
    never sourced from .env (they must come from Secret Manager).
    """
 
    if not os.path.exists(path):
        return
 
    ignored = {"META_APP_ID", "META_APP_SECRET"}
 
    with open(path, "r", encoding="utf-8") as f:
        for raw in f.readlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
 
            key, value = line.split("=", 1)
            key = key.strip()
            if key in ignored:
                continue
 
            value = value.strip().strip("'").strip('"')
            # Only set if not already present (env should win over .env).
            os.environ.setdefault(key, value)
 
 
def _get_secret_manager_client(service_account_file: Optional[str]) -> secretmanager.SecretManagerServiceClient:
    if service_account_file:
        creds = service_account.Credentials.from_service_account_file(service_account_file)
        return secretmanager.SecretManagerServiceClient(credentials=creds)
    return secretmanager.SecretManagerServiceClient()
 
 
def _access_secret_version(
    *,
    client: secretmanager.SecretManagerServiceClient,
    secret_resource_or_version: str,
    version: str = "latest",
) -> str:
    """
    Accepts either:
    - a secret resource: projects/.../secrets/NAME
    - a secret version: projects/.../secrets/NAME/versions/V
    """
    name = secret_resource_or_version
    if "/versions/" not in name:
        name = f"{name}/versions/{version}"
 
    resp = client.access_secret_version(name=name)
    return resp.payload.data.decode("utf-8").strip()
 
 
@dataclass(frozen=True)
class Settings:
    meta_api_version: str
    meta_app_id: Optional[str]
    meta_app_secret: Optional[str]
    meta_redirect_uri: Optional[str]
    meta_page_id: Optional[str]
    meta_scopes: str
 
    gsm_secret_version: str
    gcp_service_account_file: Optional[str]
 
    state_ttl_seconds: int

    google_client_id: Optional[str]
    google_client_secret: Optional[str]
    google_scopes: str
    allowed_emails: Set[str]
    allowed_domains: Set[str]
    session_secret_key: str
 
    @classmethod
    def from_env(cls) -> "Settings":
        meta_api_version = os.getenv("META_API_VERSION", "v24.0")
        meta_scopes = "pages_show_list,pages_read_engagement,pages_manage_posts"
 
        gsm_secret_version = os.getenv(
            "GSM_SECRET_VERSION",
            "projects/358205627399/secrets/META_PAGE_ACCESS_TOKEN/versions/latest",
        )
        gcp_service_account_file = os.getenv("GCP_SERVICE_ACCOUNT_FILE") or None
        if not gcp_service_account_file and os.path.exists("credentials.json"):
            # Helpful local default; in Cloud Run this file shouldn't exist.
            gcp_service_account_file = "credentials.json"
 
        state_ttl_seconds = int(os.getenv("STATE_TTL_SECONDS", "600"))
        meta_page_id = "101656079664966"
 
        oauth_client_id = os.getenv("OAUTH_CLIENT_ID",
                                    "projects/358205627399/secrets/OAUTH_CLIENT_ID/versions/latest",
        )
        oauth_client_secret = os.getenv("OAUTH_CLIENT_SECRET",
                                        "projects/358205627399/secrets/OAUTH_CLIENT_SECRET/versions/latest",
        )

        oauth_scopes = "openid email profile"

        allowed_emails_raw =  "ziyad.bekrar@student-cs.fr"
        allowed_domains_raw =  ""
        allowed_emails = {e.strip().lower() for e in allowed_emails_raw.split(",") if e.strip()}
        allowed_domains = {d.strip().lower() for d in allowed_domains_raw.split(",") if d.strip()}

        # Used by Starlette SessionMiddleware. Required for stable sessions in prod.
        session_secret_key = os.getenv("SESSION_SECRET_KEY") or secrets.token_urlsafe(32)


        # Load Meta app credentials from Secret Manager (NOT from .env).
        client = _get_secret_manager_client(gcp_service_account_file)
        meta_app_id = None
        meta_app_secret = None
        try:
            meta_redirect_uri = _access_secret_version(
                client=client,
                secret_resource_or_version=META_REDIRECT_URI_SECRET_RESOURCE,
                version="latest",
            )
            meta_app_id = _access_secret_version(
                client=client,
                secret_resource_or_version=META_APP_ID_SECRET_RESOURCE,
                version="latest",
            )
            meta_app_secret = _access_secret_version(
                client=client,
                secret_resource_or_version=META_APP_SECRET_SECRET_RESOURCE,
                version="latest",
            )
        except gcp_exceptions.GoogleAPICallError as e:
            # Keep them as None; routes will show a helpful error page.
            # (We don't want to crash import-time in environments without GCP access.)
            meta_app_id = None
            meta_app_secret = None
 
        return cls(
            meta_api_version=meta_api_version,
            meta_app_id=meta_app_id,
            meta_app_secret=meta_app_secret,
            meta_redirect_uri=meta_redirect_uri,
            meta_page_id=meta_page_id,
            meta_scopes=meta_scopes,
            gsm_secret_version=gsm_secret_version,
            gcp_service_account_file=gcp_service_account_file,
            state_ttl_seconds=state_ttl_seconds,
            google_client_id=oauth_client_id,
            google_client_secret=oauth_client_secret,
            google_scopes=oauth_scopes,
            allowed_emails=allowed_emails,
            allowed_domains=allowed_domains,
            session_secret_key=session_secret_key,
        )


def is_email_allowed(settings: Settings, email: str) -> bool:
    email_l = (email or "").strip().lower()
    if not email_l:
        return False
    if not settings.allowed_emails and not settings.allowed_domains:
        # Default-safe: if no allowlist is configured, deny access.
        return False
    if email_l in settings.allowed_emails:
        return True
    if "@" in email_l:
        domain = email_l.split("@", 1)[1]
        if domain in settings.allowed_domains:
            return True
    return False
 
 
def build_meta_oauth_dialog_url(settings: Settings, *, state: str) -> str:
    if not settings.meta_redirect_uri:
        raise ValueError("META_REDIRECT_URI is required")
    if not settings.meta_app_id:
        raise ValueError("Meta app id missing (Secret Manager access failed?)")
 
    base = f"https://www.facebook.com/{settings.meta_api_version}/dialog/oauth"
    params = {
        "client_id": settings.meta_app_id,
        "redirect_uri": settings.meta_redirect_uri,
        "state": state,
        "response_type": "code",
        "scope": settings.meta_scopes,
    }
    return f"{base}?{urllib.parse.urlencode(params)}"
 
 
def make_signed_state(secret: str, *, ttl_seconds: int) -> str:
    # token = base64url(json) + "." + base64url(hmac)
    now = int(time.time())
    payload = {
        "ts": now,
        "nonce": secrets.token_urlsafe(16),
        "ttl": int(ttl_seconds),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = _b64url_encode(payload_bytes)
 
    sig = hmac.new(secret.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{payload_b64}.{sig_b64}"
 
 
def verify_signed_state(state: str, secret: str, *, ttl_seconds: int) -> bool:
    try:
        payload_b64, sig_b64 = state.split(".", 1)
        expected_sig = hmac.new(
            secret.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        provided_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return False
 
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        ts = int(payload.get("ts", 0))
        now = int(time.time())
        return (now - ts) <= int(ttl_seconds)
    except Exception:
        return False
 
 
async def exchange_code_for_long_lived_user_access_token(settings: Settings, *, code: str) -> str:
    """
    Exchanges Meta OAuth `code` into a long-lived user access token.
    """
    if not (settings.meta_app_id and settings.meta_app_secret and settings.meta_redirect_uri):
        raise ValueError("Missing Meta OAuth configuration")
 
    token_url = f"https://graph.facebook.com/{settings.meta_api_version}/oauth/access_token"
 
    async with httpx.AsyncClient(timeout=20) as client:
        # Step 1: exchange code for short-lived token
        r1 = await client.get(
            token_url,
            params={
                "client_id": settings.meta_app_id,
                "client_secret": settings.meta_app_secret,
                "redirect_uri": settings.meta_redirect_uri,
                "code": code,
            },
        )
        if r1.status_code >= 400:
            raise ValueError(f"Meta token exchange failed: {r1.status_code} {r1.text}")
        short_token = r1.json().get("access_token")
        if not short_token:
            raise ValueError("Meta did not return an access_token (short-lived)")
 
        # Step 2: exchange for long-lived token
        r2 = await client.get(
            token_url,
            params={
                "grant_type": "fb_exchange_token",
                "client_id": settings.meta_app_id,
                "client_secret": settings.meta_app_secret,
                "fb_exchange_token": short_token,
            },
        )
        if r2.status_code >= 400:
            raise ValueError(f"Meta long-lived exchange failed: {r2.status_code} {r2.text}")
        long_token = r2.json().get("access_token")
        if not long_token:
            raise ValueError("Meta did not return an access_token (long-lived)")
 
        return long_token


async def exchange_user_token_for_page_access_token(settings: Settings, *, user_access_token: str) -> str:
    """
    Uses `/me/accounts` to retrieve a page access token.

    - If META_PAGE_ID is set, selects that page.
    - If META_PAGE_ID is not set and exactly one page is available, selects it.
    - Otherwise raises a ValueError asking to set META_PAGE_ID.
    """
    if not user_access_token:
        raise ValueError("Missing user access token; cannot fetch page access token.")

    url = f"https://graph.facebook.com/{settings.meta_api_version}/me/accounts"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(
            url,
            params={
                "access_token": user_access_token,
                "fields": "id,name,access_token",
            },
        )

    if resp.status_code >= 400:
        raise ValueError(f"Meta page token retrieval failed: {resp.status_code} {resp.text}")

    payload = resp.json()
    pages = payload.get("data") or []
    if not pages:
        raise ValueError(
            "No pages found for this user. Ensure your app has required page scopes and the user has page access."
        )

    if settings.meta_page_id:
        for page in pages:
            if str(page.get("id")) == str(settings.meta_page_id):
                page_token = page.get("access_token")
                if not page_token:
                    raise ValueError(f"Page {settings.meta_page_id} found but no access_token was returned.")
                return page_token
        available = ", ".join(str(p.get("id")) for p in pages if p.get("id"))
        raise ValueError(
            f"META_PAGE_ID={settings.meta_page_id} not found in /me/accounts. Available page ids: {available}"
        )

    if len(pages) == 1:
        page_token = pages[0].get("access_token")
        if not page_token:
            raise ValueError("Single page found but no access_token was returned.")
        return page_token

    available = ", ".join(f"{p.get('name', 'unknown')}({p.get('id', '?')})" for p in pages)
    raise ValueError(
        "Multiple pages found. Set META_PAGE_ID to choose one page. "
        f"Available pages: {available}"
    )
 
 
def upload_to_google_secret_manager_if_changed(
    *,
    token: str,
    secret_version: str,
    service_account_file: Optional[str],
) -> Tuple[bool, str]:
    """
    Writes `token` to Secret Manager as a new secret version, but only if it differs
    from the currently active version.
 
    Returns (updated, message).
    """
    if not token:
        return False, "No token was generated."
 
    client = _get_secret_manager_client(service_account_file)
 
    # Read current value (if any)
    current_value: Optional[str] = None
    try:
        current_value = _access_secret_version(
            client=client,
            secret_resource_or_version=secret_version,
            version="latest",
        )
    except gcp_exceptions.NotFound:
        current_value = None
    except gcp_exceptions.PermissionDenied as e:
        return False, f"Permission denied reading current secret version: {str(e)}"
    except gcp_exceptions.GoogleAPICallError as e:
        return False, f"Error reading current secret version: {str(e)}"
 
    if current_value == token:
        return False, "Token unchanged; no new Secret Manager version created."
 
    # Add new version
    try:
        parent = secret_version.split("/versions/", 1)[0] if "/versions/" in secret_version else secret_version
        payload = secretmanager.SecretPayload(data=token.encode("utf-8"))
        client.add_secret_version(parent=parent, payload=payload)
        return True, "Stored new token version in Google Secret Manager."
    except gcp_exceptions.PermissionDenied as e:
        return False, f"Permission denied adding secret version: {str(e)}"
    except gcp_exceptions.GoogleAPICallError as e:
        return False, f"Error adding secret version: {str(e)}"

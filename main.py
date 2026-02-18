import os
import json
import urllib.parse
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from helpers import (
    Settings,
    build_meta_oauth_dialog_url,
    exchange_code_for_long_lived_user_access_token,
    exchange_user_token_for_page_access_token,
    is_email_allowed,
    load_dotenv_file,
    make_signed_state,
    upload_to_google_secret_manager_if_changed,
    verify_signed_state,
)

from authlib.integrations.starlette_client import OAuth, OAuthError  # type: ignore[import-not-found]

load_dotenv_file()
settings = Settings.from_env()

app = FastAPI()

oauth = OAuth()
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=settings.google_client_id,
    client_secret=settings.google_client_secret,
    client_kwargs={"scope": settings.google_scopes},
)


def _current_user(request: Request) -> Optional[dict]:
    return (request.session or {}).get("user")


def _auth_error_html(message: str, *, status_code: int = 403) -> HTMLResponse:
    return HTMLResponse(
        f"""
        <html>
          <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
            <h2>Access denied</h2>
            <p>{message}</p>
            <p><a href="/logout">Sign out</a></p>
          </body>
        </html>
        """.strip(),
        status_code=status_code,
    )


@app.middleware("http")
async def require_google_login(request: Request, call_next):
    public_paths = {"/login", "/auth/callback", "/logout"}
    if (
        request.url.path in public_paths
        or request.url.path in {"/openapi.json", "/redoc"}
        or request.url.path.startswith("/docs")
    ):
        return await call_next(request)

    user = _current_user(request)
    if not user:
        next_url = str(request.url)
        return RedirectResponse(url=f"/login?next={urllib.parse.quote(next_url, safe='')}", status_code=302)

    email = (user.get("email") or "").strip()
    if not is_email_allowed(settings, email):
        return _auth_error_html(
            f"Your Google account ({email or 'unknown'}) is not on the allowlist.",
            status_code=403,
        )

    return await call_next(request)


# IMPORTANT: SessionMiddleware must wrap the function middleware above.
# FastAPI inserts function middleware before add_middleware() entries,
# so we add SessionMiddleware after declaring @app.middleware handlers.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret_key,
    https_only=True,  
    same_site="lax",
)


def _missing_config_error_html(*items: str) -> HTMLResponse:
    return HTMLResponse(
        f"""
        <html>
          <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
            <h2>Missing configuration</h2>
            <p>Fix these items and restart the server:</p>
            <pre>{chr(10).join(items)}</pre>
            <p>Tip: copy <code>.env.example</code> to <code>.env</code> for non-secret config.</p>
          </body>
        </html>
        """.strip(),
        status_code=500,
    )


@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    user = _current_user(request) or {}
    email = (user.get("email") or "").strip()
    return HTMLResponse(
        f"""
        <html>
          <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
            <h2>TokenMeta</h2>
            <p>Signed in as <b>{email}</b>.</p>
            <p><a href="/meta-auth">Start Meta OAuth</a></p>
            <p><a href="/logout">Sign out</a></p>
          </body>
        </html>
        """.strip()
    )


@app.get("/login")
async def login(request: Request, next: Optional[str] = None):
    if not (settings.google_client_id and settings.google_client_secret):
        return _missing_config_error_html("GOOGLE_CLIENT_ID (env var)", "GOOGLE_CLIENT_SECRET (env var)")

    # Prevent open-redirects: only allow same-host absolute URLs or relative paths.
    dest = next or "/"
    try:
        parsed = urllib.parse.urlparse(dest)
        if parsed.scheme and parsed.netloc and parsed.netloc != request.url.netloc:
            dest = "/"
    except Exception:
        dest = "/"

    request.session["next"] = dest
    redirect_uri = str(request.url_for("auth_callback"))
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        # Authlib may already populate token["userinfo"] when id_token + nonce are present.
        userinfo = token.get("userinfo")
        if not userinfo:
            # Fallback for configurations where id_token is not returned.
            userinfo = await oauth.google.userinfo(token=token)
    except OAuthError as e:
        return _auth_error_html(f"Google OAuth failed: {str(e)}", status_code=400)
    except Exception as e:
        return _auth_error_html(f"Google userinfo retrieval failed: {str(e)}", status_code=400)

    email = (userinfo.get("email") or "").strip().lower()
    if not is_email_allowed(settings, email):
        return _auth_error_html(f"Your Google account ({email or 'unknown'}) is not on the allowlist.", status_code=403)

    request.session["user"] = {
        "email": email,
        "name": userinfo.get("name"),
        "picture": userinfo.get("picture"),
    }
    dest = request.session.pop("next", "/") or "/"
    return RedirectResponse(url=dest, status_code=302)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/meta-auth")
async def meta_auth(request: Request):
    """
    Starts the Meta (Facebook) OAuth flow.
    The user will be taken to Meta and asked to authorize your app, returning an access token.
    """

    if not (settings.meta_app_id and settings.meta_app_secret):
        return _missing_config_error_html(
            "Secret Manager access failed for:",
            "projects/358205627399/secrets/META_APP_ID/versions/latest",
            "projects/358205627399/secrets/META_APP_SECRET/versions/latest",
        )

    # State is signed (no cookie dependency).
    state = make_signed_state(
        settings.meta_app_secret,
        ttl_seconds=settings.state_ttl_seconds,
    )
    redirect_url = build_meta_oauth_dialog_url(settings, state=state)
    return RedirectResponse(url=redirect_url, status_code=302)


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

    if not (settings.meta_app_id and settings.meta_app_secret and settings.meta_redirect_uri):
        missing = []
        if not settings.meta_redirect_uri:
            missing.append("META_REDIRECT_URI (env var)")
        if not (settings.meta_app_id and settings.meta_app_secret):
            missing.extend(
                [
                    "Secret Manager access failed for:",
                    "projects/358205627399/secrets/META_APP_ID/versions/latest",
                    "projects/358205627399/secrets/META_APP_SECRET/versions/latest",
                ]
            )
        return _missing_config_error_html(*missing)

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

    if not state or not verify_signed_state(
        state,
        settings.meta_app_secret,
        ttl_seconds=settings.state_ttl_seconds,
    ):
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

    try:
        long_user_access_token = await exchange_code_for_long_lived_user_access_token(
            settings, code=code
        )
        pages_payload = await exchange_user_token_for_page_access_token(
            settings,
            user_access_token=long_user_access_token,
        )
    except ValueError as e:
        return HTMLResponse(
            f"""
            <html>
              <body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
                <h2>Failed</h2>
                <p>{str(e)}</p>
                <p><a href="/meta-auth">Try again</a></p>
              </body>
            </html>
            """.strip(),
            status_code=400,
        )

    updated, message = upload_to_google_secret_manager_if_changed(
        token=json.dumps(pages_payload, ensure_ascii=True),
        secret_version=settings.gsm_secret_version,
        service_account_file=settings.gcp_service_account_file,
    )

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
    return resp

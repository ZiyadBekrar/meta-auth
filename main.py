import os
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from helpers import (
    Settings,
    build_meta_oauth_dialog_url,
    exchange_code_for_long_lived_user_access_token,
    load_dotenv_file,
    make_signed_state,
    upload_to_google_secret_manager_if_changed,
    verify_signed_state,
)

load_dotenv_file()
settings = Settings.from_env()

app = FastAPI()


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
        long_access_token = await exchange_code_for_long_lived_user_access_token(
            settings, code=code
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
        token=long_access_token,
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

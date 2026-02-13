import os
import datetime as dt
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore
except Exception:  # pragma: no cover
    AsyncIOScheduler = None  # type: ignore

from helpers import (
    Settings,
    build_meta_oauth_dialog_url,
    compute_alert_time_utc,
    compute_expires_at_utc,
    exchange_code_for_long_lived_user_access_token,
    load_dotenv_file,
    make_signed_state,
    send_gmail_smtp_email,
    upload_to_google_secret_manager_if_changed,
    verify_signed_state,
)

load_dotenv_file()
settings = Settings.from_env()

app = FastAPI()

_scheduler = AsyncIOScheduler(timezone="UTC") if AsyncIOScheduler is not None else None
_ALERT_JOB_ID = "meta-token-expiry-email"


@app.on_event("startup")
async def _start_scheduler() -> None:
    if _scheduler is None:
        return
    if not _scheduler.running:
        _scheduler.start()

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

    if not (settings.meta_app_id and settings.meta_app_secret):
        return _missing_env_error_html("META_APP_ID", "META_APP_SECRET")

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
        long_access_token, expires_in = await exchange_code_for_long_lived_user_access_token(
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

    # Schedule expiry alert email when token is updated and expiry is known.
    if updated:
        expires_at = compute_expires_at_utc(expires_in)
        if expires_at and settings.SMTP_PASSWORD and _scheduler is not None:
            alert_at = compute_alert_time_utc(
                expires_at_utc=expires_at,
                days_before=settings.alert_days_before_expiry,
            )

            # If already within the alert window, send ASAP.
            now = dt.datetime.now(dt.timezone.utc)
            run_at = alert_at if alert_at > now else (now + dt.timedelta(seconds=5))

            _scheduler.add_job(
                send_gmail_smtp_email,
                trigger="date",
                id=_ALERT_JOB_ID,
                replace_existing=True,
                run_date=run_at,
                kwargs={
                    "gmail_from": settings.SMTP_FROM,
                    "gmail_app_password": settings.SMTP_PASSWORD,
                    "to_email": settings.SMTP_USER,
                    "subject": "Meta token expiring soon (refresh needed)",
                    "body": (
                        "Your Meta long-lived access token is nearing expiry.\n\n"
                        f"Estimated expiry (UTC): {expires_at.isoformat()}\n"
                        f"Alert scheduled at (UTC): {run_at.isoformat()}\n\n"
                        "Refresh it by visiting:\n"
                        f"{settings.meta_redirect_uri.replace('/meta-auth/callback', '/meta-auth')}\n"
                    ),
                },
            )
            message = f"{message} Email scheduled for {run_at.isoformat()} (UTC)."
        elif expires_at and settings.SMTP_PASSWORD and _scheduler is None:
            message = f"{message} Email not scheduled (apscheduler not installed)."
        elif expires_at and not settings.SMTP_PASSWORD:
            message = f"{message} Email not scheduled (missing GMAIL_APP_PASSWORD)."
        else:
            message = f"{message} Email not scheduled (missing expires_in from Meta)."

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

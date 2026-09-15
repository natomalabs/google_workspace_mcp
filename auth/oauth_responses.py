"""
Shared OAuth callback response templates.

Provides reusable HTML response templates for OAuth authentication flows
to eliminate duplication between server.py and oauth_callback_server.py.

Security note: /oauth2callback is reachable by anyone who can get a URL loaded in
the victim's browser, and every value interpolated into these templates may derive
from attacker-controlled query parameters or from library exception text that
embeds them. All interpolated values are therefore HTML-escaped, and the responses
carry a restrictive CSP so that any escaping gap cannot become script execution.
"""

import html
import re
import uuid
from fastapi.responses import HTMLResponse
from typing import Optional

# A correlation reference is always a short opaque token. Anything else passed to
# create_server_error_response is treated as an accidental exception string and
# dropped rather than rendered, so the CWE-209 leak cannot be reintroduced by a
# caller that forgets the contract.
_ERROR_REFERENCE_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")

# These pages are static HTML with no external resources and no legitimate need
# for scripting beyond the inline auto-close timer, so lock everything else down.
# 'unsafe-inline' is required for the inline <script> that closes the window;
# script-src is otherwise 'none', and no other resource type is permitted.
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; "
        "script-src 'unsafe-inline'; "
        "style-src 'unsafe-inline'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def new_error_reference() -> str:
    """
    Generate a short opaque reference to correlate a browser-visible error with
    the full detail in the server log.
    """
    return uuid.uuid4().hex[:12]


def create_error_response(error_message: str, status_code: int = 400) -> HTMLResponse:
    """
    Create a standardized error response for OAuth failures.

    Args:
        error_message: The error message to display. HTML-escaped before rendering;
            callers must still ensure it contains no secrets or internal paths.
        status_code: HTTP status code (default 400)

    Returns:
        HTMLResponse with error page
    """
    safe_message = html.escape(error_message, quote=True)
    content = f"""
        <html>
        <head><title>Authentication Error</title></head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; text-align: center;">
            <h2 style="color: #d32f2f;">Authentication Error</h2>
            <p>{safe_message}</p>
            <p>Please ensure you grant the requested permissions. You can close this window and try again.</p>
            <script>setTimeout(function() {{ window.close(); }}, 10000);</script>
        </body>
        </html>
    """
    return HTMLResponse(
        content=content, status_code=status_code, headers=_SECURITY_HEADERS
    )


def create_success_response(verified_user_id: Optional[str] = None) -> HTMLResponse:
    """
    Create a standardized success response for OAuth authentication.

    Args:
        verified_user_id: The authenticated user's email (optional)

    Returns:
        HTMLResponse with success page
    """
    # Handle the case where no user ID is provided
    user_display = html.escape(
        verified_user_id if verified_user_id else "Google User", quote=True
    )

    content = f"""<html>
<head>
    <title>Authentication Successful</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg,#0f172a,#1e293b,#334155);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #1a1a1a;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }}

        .container {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 60px;
            border-radius: 20px;
            box-shadow: 0 30px 60px rgba(0, 0, 0, 0.12);
            text-align: center;
            max-width: 480px;
            width: 90%;
            transform: translateY(-20px);
            animation: slideUp 0.6s ease-out;
        }}

        @keyframes slideUp {{
            from {{
                opacity: 0;
                transform: translateY(0);
            }}
            to {{
                opacity: 1;
                transform: translateY(-20px);
            }}
        }}

        .icon {{
            width: 80px;
            height: 80px;
            margin: 0 auto 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            color: white;
            animation: pulse 2s ease-in-out infinite;
        }}

        @keyframes pulse {{
            0%, 100% {{
                transform: scale(1);
            }}
            50% {{
                transform: scale(1.05);
            }}
        }}

        h1 {{
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .message {{
            font-size: 16px;
            line-height: 1.6;
            color: #4a5568;
            margin-bottom: 20px;
        }}

        .user-id {{
            font-weight: 600;
            color: #667eea;
            padding: 4px 12px;
            background: rgba(102, 126, 234, 0.1);
            border-radius: 6px;
            display: inline-block;
            margin: 0 4px;
        }}

        .button {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 16px 40px;
            border: none;
            border-radius: 30px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 30px;
            display: inline-block;
            text-decoration: none;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}

        .button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 7px 20px rgba(102, 126, 234, 0.4);
        }}

        .button:active {{
            transform: translateY(0);
        }}

        .auto-close {{
            font-size: 13px;
            color: #a0aec0;
            margin-top: 30px;
            opacity: 0.8;
        }}
    </style>
    <script>
        setTimeout(function() {{
            window.close();
        }}, 10000);
    </script>
</head>
<body>
    <div class="container">
        <div class="icon">✓</div>
        <h1>Authentication Successful</h1>
        <div class="message">
            You've been authenticated as <span class="user-id">{user_display}</span>
        </div>
        <div class="message">
            Your credentials have been securely saved. You can now close this window and retry your original command.
        </div>
        <button class="button" onclick="window.close()">Close Window</button>
        <div class="auto-close">This window will close automatically in 10 seconds</div>
    </div>
</body>
</html>"""
    return HTMLResponse(content=content, headers=_SECURITY_HEADERS)


def create_server_error_response(error_reference: Optional[str] = None) -> HTMLResponse:
    """
    Create a standardized server error response for OAuth processing failures.

    Deliberately does NOT render the underlying exception text. The previous
    behaviour interpolated raw ``str(e)`` from the token exchange into the page,
    which leaked the absolute client-secrets path, the configured redirect_uri and
    scope list, and partial token-endpoint responses to any unauthenticated caller
    who could get a crafted /oauth2callback URL loaded in a browser — and, where a
    library exception embedded attacker-supplied URL bytes, became a reflected XSS
    sink. Callers must log the detail server-side and pass only the correlation
    reference here.

    Args:
        error_reference: Opaque id (see ``new_error_reference``) that an operator
            can grep for in the server log. Optional.

    Returns:
        HTMLResponse with server error page
    """
    reference_html = ""
    if error_reference and _ERROR_REFERENCE_RE.fullmatch(error_reference):
        safe_reference = html.escape(error_reference, quote=True)
        reference_html = (
            f'<p style="color: #666; font-size: 13px;">Reference: '
            f"<code>{safe_reference}</code></p>"
        )

    content = f"""
        <html>
        <head><title>Authentication Processing Error</title></head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; text-align: center;">
            <h2 style="color: #d32f2f;">Authentication Processing Error</h2>
            <p>An unexpected error occurred while processing your authentication.</p>
            <p>Please try again. You can close this window.</p>
            {reference_html}
            <script>setTimeout(function() {{ window.close(); }}, 10000);</script>
        </body>
        </html>
    """
    return HTMLResponse(content=content, status_code=500, headers=_SECURITY_HEADERS)
import base64
from functools import wraps

from flask import g, jsonify, request

from ..models import AnonymousUser
from ..security import (
    AUTH_DISABLED,
    AUTH_INVALID,
    AUTH_LOCKED,
    AUTH_MFA_FAILED,
    AUTH_MFA_REQUIRED,
    AUTH_OK,
    authenticate_credentials,
    issue_api_token,
    password_expired,
    resolve_bearer_token,
    validate_scopes,
)
from . import api
from .errors import bad_request, forbidden, unauthorized

# Bearer-token resolution errors -> (status_code, message)
_BEARER_ERRORS = {
    "expired": (401, "Token has expired."),
    "revoked": (401, "Token has been revoked."),
    "inactive": (403, "Account is disabled."),
    "invalid": (401, "Invalid or expired token."),
    "missing": (
        401,
        "Authentication required. Include a valid Bearer token in the Authorization header.",
    ),
}

# Credential (Basic/JSON) authentication statuses -> (status_code, message)
_CREDENTIAL_ERRORS = {
    AUTH_INVALID: (401, "Invalid email or password."),
    AUTH_MFA_REQUIRED: (
        403,
        "Multi-factor authentication required. Include a valid X-MFA-OTP header "
        "or an 'otp' JSON field.",
    ),
    AUTH_MFA_FAILED: (401, "Invalid multi-factor authentication code."),
    AUTH_LOCKED: (403, "Account is temporarily locked due to failed login attempts."),
    AUTH_DISABLED: (403, "Account has been disabled."),
}


def _parse_basic_header():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return None, None
    try:
        encoded = auth_header[6:].strip()
        decoded = base64.b64decode(encoded).decode("utf-8")
        email, password = decoded.split(":", 1)
        return email, password
    except Exception:  # noqa: BLE001 - malformed header simply fails authentication
        return None, None


def get_auth_user_from_request():
    """Resolve the API caller once per request (Bearer opaque > legacy > Basic)."""
    g.auth_method = None
    g.auth_token = None  # ApiToken row when an opaque token was used
    g.auth_scopes = None  # None means "legacy/full access"
    g.auth_error = None

    auth_header = request.headers.get("Authorization", "")

    # 1. Bearer token: revocable+scoped ApiToken first, then legacy signed token.
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        user, token_row, error = resolve_bearer_token(token)
        if user is not None:
            g.auth_method = "bearer"
            g.auth_token = token_row
            g.auth_scopes = token_row.scope_list if token_row is not None else None
            return user
        g.auth_error = error if error != "missing" else "missing"
        return None

    # 2. Basic auth (email:password), sharing the lockout/MFA policy with the web UI.
    if auth_header.startswith("Basic "):
        email, password = _parse_basic_header()
        if email is None:
            g.auth_error = AUTH_INVALID
            return None
        otp = request.headers.get("X-MFA-OTP")
        user, status = authenticate_credentials(email, password, otp=otp, source="api")
        if status == AUTH_OK:
            g.auth_method = "basic"
            return user
        g.auth_error = status
        return None

    g.auth_error = "missing"
    return None


@api.before_request
def before_request():
    user = get_auth_user_from_request()
    g.current_user = user if user is not None else AnonymousUser()
    # Credentials were supplied but rejected (bad/expired/revoked token,
    # wrong password, ...). Fail loudly even on public endpoints instead of
    # silently downgrading to anonymous access.
    error = getattr(g, "auth_error", None)
    if user is None and error not in (None, "missing"):
        return _auth_failure_response()
    # B1/B2: credentials for an account that must change its password
    # (admin-issued flag, or over the configured maximum age) are frozen at
    # the API until a new password is set through the web UI.
    if user is not None and user.must_change_password:
        response = jsonify(
            {
                "error": "password change required",
                "message": "You must change your password before using the API.",
            }
        )
        response.status_code = 403
        return response
    if user is not None and password_expired(user):
        response = jsonify(
            {
                "error": "password expired",
                "message": "Your password has expired. Choose a new one before using the API.",
            }
        )
        response.status_code = 403
        return response


def _auth_failure_response():
    """Translate the recorded auth error into a precise 401/403 JSON response."""
    error = getattr(g, "auth_error", None) or "missing"
    if error in _BEARER_ERRORS:
        code, message = _BEARER_ERRORS[error]
    elif error in _CREDENTIAL_ERRORS:
        code, message = _CREDENTIAL_ERRORS[error]
    else:
        code, message = 401, "Authentication failed."
    response = unauthorized(message) if code == 401 else forbidden(message)
    return response


def token_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.current_user.is_authenticated:
            return _auth_failure_response()
        return f(*args, **kwargs)

    return decorated


def permission_required_api(permission):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not g.current_user.is_authenticated:
                return unauthorized(
                    "Authentication required. Include a valid Bearer token in the Authorization header."
                )
            if not g.current_user.confirmed:
                return forbidden("Account is not confirmed. Please confirm your email address.")
            if not g.current_user.can(permission):
                return forbidden("Insufficient permissions to perform this action.")
            return f(*args, **kwargs)

        return decorated

    return decorator


def scope_required(scope):
    """Enforce an OAuth-style scope for opaque tokens (legacy tokens are full-access)."""

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            scopes = getattr(g, "auth_scopes", None)
            if scopes is not None and scope not in scopes:
                return forbidden(f"Token is missing the required scope '{scope}'.")
            return f(*args, **kwargs)

        return decorated

    return decorator


def _credential_failure(status):
    """Map a credential-authentication status to its 401/403 JSON response."""
    code, message = _CREDENTIAL_ERRORS.get(status, (401, "Invalid email or password."))
    return forbidden(message) if code == 403 else unauthorized(message)


@api.route("/tokens", methods=["POST"])
def get_token():
    """Issue an opaque, revocable, scoped API token from account credentials.

    Accepts credentials via ``Authorization: Basic`` or a JSON body::

        {"email": "...", "password": "...", "otp": "123456",
         "name": "cli", "scopes": ["posts:read"], "expiration": 3600}
    """
    data = request.get_json(silent=True) or {}

    if g.current_user.is_authenticated and g.auth_method == "basic":
        # Credentials already verified (and audited) by the Basic-auth preflight.
        user = g.current_user
    elif data.get("email") is not None:
        user, status = authenticate_credentials(
            data.get("email"),
            data.get("password"),
            otp=data.get("otp") or request.headers.get("X-MFA-OTP"),
            source="api",
        )
        if status != AUTH_OK:
            return _credential_failure(status)
    elif g.auth_error and g.auth_error != "missing":
        # Basic header was present but authentication failed in the preflight.
        return _credential_failure(g.auth_error)
    else:
        return unauthorized("Credentials required. Use Basic auth or a JSON body.")

    if not user.confirmed:
        return forbidden("Account is not confirmed.")

    # Optional scope selection & expiry.
    scopes = data.get("scopes")
    if scopes is not None:
        if not isinstance(scopes, list):
            return bad_request("'scopes' must be a list of scope names.")
        valid, unknown = validate_scopes(scopes)
        if unknown:
            return bad_request(f"Unknown scope(s): {', '.join(unknown)}")
        scopes = valid

    token, row = issue_api_token(
        user,
        name=data.get("name") or "default",
        scopes=scopes,
        ttl=data.get("expiration"),
    )
    ttl = int((row.expires_at - row.created_at).total_seconds()) if row.expires_at else 0
    return jsonify(
        {
            "token": token,
            "expiration": ttl,
            "token_id": row.id,
            "scopes": row.scope_list,
            "user": user.to_json(),
        }
    )

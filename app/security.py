"""IAM services: audit trail, credential authentication (lockout-aware),
MFA helpers, server-side sessions and API-token issuing.

Keeping these flows in one module guarantees the web UI and the REST API
enforce exactly the same security policy.
"""

import base64
import io
import json
import uuid
from datetime import timedelta, timezone

import qrcode
from flask import current_app, g, has_request_context, request, session
from flask_login import current_user, login_user, logout_user

from . import db
from .models import (
    AccessLog,
    ApiToken,
    AuditEvent,
    Permission,
    Role,
    User,
    UserSession,
    as_naive_utc,
    utc_now,
)


class Event:
    """Canonical audit event names."""

    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGIN_LOCKED = "auth.login.locked"
    LOGOUT = "auth.logout"
    API_AUTH_SUCCESS = "auth.api.success"
    API_AUTH_FAILED = "auth.api.failed"
    MFA_CHALLENGE = "auth.mfa.challenge"
    MFA_SUCCESS = "auth.mfa.success"
    MFA_FAILED = "auth.mfa.failed"
    MFA_ENABLED = "auth.mfa.enabled"
    MFA_DISABLED = "auth.mfa.disabled"
    PASSWORD_CHANGED = "account.password.changed"
    PASSWORD_RESET_REQUESTED = "account.password.reset_requested"
    PASSWORD_RESET_COMPLETED = "account.password.reset_completed"
    EMAIL_CHANGED = "account.email.changed"
    ACCOUNT_CONFIRMED = "account.confirmed"
    REGISTER = "account.registered"
    SESSION_STARTED = "session.started"
    SESSION_REVOKED = "session.revoked"
    SESSION_EXPIRED = "session.expired"
    TOKEN_ISSUED = "token.issued"
    TOKEN_REVOKED = "token.revoked"
    USER_ROLE_CHANGED = "admin.user.role_changed"
    USER_DISABLED = "admin.user.disabled"
    USER_ENABLED = "admin.user.enabled"
    USER_UNLOCKED = "admin.user.unlocked"
    USER_CONFIRMED = "admin.user.confirmed"
    USER_PASSWORD_RESET_SENT = "admin.user.password_reset_sent"
    USER_MFA_RESET = "admin.user.mfa_reset"
    USER_SESSIONS_REVOKED = "admin.user.sessions_revoked"
    USER_PASSWORD_CHANGE_REQUIRED = "admin.user.password_change_required"
    USER_DELETED = "admin.user.deleted"
    ROLE_CREATED = "admin.role.created"
    ROLE_UPDATED = "admin.role.updated"
    ROLE_DELETED = "admin.role.deleted"
    COMMENT_MODERATED = "moderation.comment.toggled"
    # Log lifecycle: reading, exporting and pruning the trails are themselves
    # security-relevant actions and therefore audited.
    AUDIT_VIEWED = "audit.viewed"
    AUDIT_EXPORTED = "audit.exported"
    ACCESS_LOG_VIEWED = "access_log.viewed"
    LOGS_PRUNED = "logs.pruned"


# ---------------------------------------------------------------------------
# Request context helpers
# ---------------------------------------------------------------------------


def client_ip():
    if not has_request_context():
        return None
    return (request.remote_addr or "")[:64] or None


def client_user_agent():
    if not has_request_context():
        return None
    return (request.headers.get("User-Agent") or "")[:256] or None


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def record_audit(
    event,
    actor=None,
    actor_label=None,
    target_type=None,
    target_id=None,
    target_label=None,
    success=True,
    detail=None,
    commit=True,
):
    """Append a structured audit event.

    Never raises: a failure to audit must not break the request being audited.
    """
    try:
        if actor_label is None and actor is not None:
            actor_label = actor.email
        entry = AuditEvent(
            event=event,
            actor_id=getattr(actor, "id", None),
            actor_label=(actor_label or "")[:128] or None,
            target_type=target_type,
            target_id=target_id,
            target_label=(target_label or "")[:128] or None,
            success=bool(success),
            ip=client_ip(),
            user_agent=client_user_agent(),
            detail=json.dumps(detail) if isinstance(detail, dict) else detail,
        )
        db.session.add(entry)
        if commit:
            db.session.commit()
        return entry
    except Exception:  # noqa: BLE001 - auditing must never break a request
        db.session.rollback()
        current_app.logger.exception("Failed to record audit event %s", event)
        return None


# ---------------------------------------------------------------------------
# Access log (structured per-request trail)
# ---------------------------------------------------------------------------

# Path prefixes whose remainder is redacted before a row is stored: these
# routes carry single-use tokens that must never leak through the log.
_SENSITIVE_PATH_PREFIXES = ("/auth/reset/", "/auth/confirm/", "/auth/change_email/")


def sanitize_path(path):
    """Redact one-time tokens embedded in a URL path.

    Query strings are never stored (``request.path`` only), so this is the
    last place a secret could travel through the access log.
    """
    path = path or "/"
    for prefix in _SENSITIVE_PATH_PREFIXES:
        if path.startswith(prefix):
            return (prefix + "***")[:256]
    return path[:256]


def _request_identity():
    """Resolve the principal the request acted as, or ``None`` for anonymous.

    The REST API authorizes via ``g.current_user`` (Bearer/Basic), the web UI
    via the Flask-Login session proxy; whichever applies wins so API rows never
    inherit a stale browser-session identity.
    """
    identity = None
    if has_request_context() and request.blueprint == "api":
        identity = g.get("current_user")
    if identity is None:
        identity = current_user
    if getattr(identity, "is_authenticated", False):
        user = getattr(identity, "_get_current_object", lambda: identity)()
        return user, getattr(user, "email", None)
    return None, None


def record_access(response, duration_ms=None):
    """Append a structured access-log row for the request being answered.

    Never raises: a failure to log access must not break the response.
    """
    try:
        if not has_request_context():
            return None
        if not current_app.config.get("BLOGG_ACCESS_LOG_ENABLED", True):
            return None
        path = request.path or "/"
        for prefix in current_app.config.get("BLOGG_ACCESS_LOG_EXCLUDE_PREFIXES") or ():
            if path.startswith(prefix):
                return None
        user, user_label = _request_identity()
        entry = AccessLog(
            user_id=getattr(user, "id", None),
            user_label=(user_label or "")[:128] or None,
            method=request.method,
            path=sanitize_path(path),
            endpoint=(request.endpoint or "")[:128] or None,
            status_code=response.status_code,
            duration_ms=duration_ms,
            ip=client_ip(),
            user_agent=client_user_agent(),
            is_api=path.startswith("/api/"),
        )
        db.session.add(entry)
        db.session.commit()
        return entry
    except Exception:  # noqa: BLE001 - logging must never break a response
        db.session.rollback()
        current_app.logger.exception(
            "Failed to record access log for %s", getattr(request, "path", "?")
        )
        return None


def prune_expired_logs(commit=True):
    """Delete audit and access records older than their retention windows.

    Retention is configured with ``BLOGG_AUDIT_RETENTION_DAYS`` and
    ``BLOGG_ACCESS_LOG_RETENTION_DAYS``; 0 (the default) keeps everything.
    Pruning is itself audited. Returns per-table deletion counts.
    """
    now = utc_now()
    counts = {"audit_events": 0, "access_logs": 0}

    audit_days = int(current_app.config.get("BLOGG_AUDIT_RETENTION_DAYS", 0) or 0)
    if audit_days > 0:
        cutoff = now - timedelta(days=audit_days)
        counts["audit_events"] = AuditEvent.query.filter(AuditEvent.timestamp < cutoff).delete(
            synchronize_session="fetch"
        )

    access_days = int(current_app.config.get("BLOGG_ACCESS_LOG_RETENTION_DAYS", 0) or 0)
    if access_days > 0:
        cutoff = now - timedelta(days=access_days)
        counts["access_logs"] = AccessLog.query.filter(AccessLog.timestamp < cutoff).delete(
            synchronize_session="fetch"
        )

    if any(counts.values()):
        record_audit(Event.LOGS_PRUNED, detail=counts, commit=False)
    if commit:
        db.session.commit()
    return counts


# ---------------------------------------------------------------------------
# Authorization guards shared by the admin UI and the admin API
# ---------------------------------------------------------------------------


def administrator_count():
    """Number of accounts whose role currently carries the ADMIN permission."""
    return (
        User.query.join(Role)
        .filter((Role.permissions.op("&")(Permission.ADMIN)) == Permission.ADMIN)
        .count()
    )


def active_administrator_count(exclude_user_id=None, exclude_role_id=None):
    """Number of *active* accounts whose role carries the ADMIN permission.

    The last-admin guards use this rather than `administrator_count()`:
    disabled accounts cannot act, so they must not count towards the
    "an administrator still exists" arithmetic.
    """
    query = User.query.join(Role).filter(
        (Role.permissions.op("&")(Permission.ADMIN)) == Permission.ADMIN,
        User.active.is_(True),
    )
    if exclude_user_id is not None:
        query = query.filter(User.id != exclude_user_id)
    if exclude_role_id is not None:
        query = query.filter(Role.id != exclude_role_id)
    return query.count()


def escape_like(value):
    r"""Escape LIKE metacharacters (``\``, ``%``, ``_``) in a user-supplied term.

    Pass the result through ``ilike(pattern, escape="\\")`` so a search for
    ``100%`` matches literal ``100%`` instead of ``100`` followed by anything.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ---------------------------------------------------------------------------
# Credential authentication with lockout policy
# ---------------------------------------------------------------------------

# Status codes returned by authenticate_credentials()
AUTH_OK = "ok"
AUTH_MFA_REQUIRED = "mfa_required"
AUTH_MFA_FAILED = "mfa_failed"
AUTH_INVALID = "invalid"
AUTH_LOCKED = "locked"
AUTH_DISABLED = "disabled"

_SOURCE_EVENTS = {
    "web": (Event.LOGIN_SUCCESS, Event.LOGIN_FAILED),
    "api": (Event.API_AUTH_SUCCESS, Event.API_AUTH_FAILED),
}


def authenticate_credentials(email, password, otp=None, source="web", record=True):
    """Verify a password (and optional OTP) under the shared lockout policy.

    Returns ``(user, status)`` where status is one of the AUTH_* constants.
    ``user`` may be None when the email is unknown.
    """
    success_event, failure_event = _SOURCE_EVENTS.get(source, _SOURCE_EVENTS["web"])
    user = User.query.filter_by(email=(email or "").strip().lower()).first()

    if user is None:
        if record:
            record_audit(
                failure_event,
                actor_label=email,
                success=False,
                detail={"reason": "unknown_email", "source": source},
            )
        return None, AUTH_INVALID

    if not user.verify_password(password or ""):
        if record:
            locked_now = user.record_failed_login()
            record_audit(
                failure_event,
                actor=user,
                success=False,
                detail={
                    "reason": "bad_password",
                    "source": source,
                    "failed_attempts": user.failed_login_attempts,
                },
            )
            if locked_now:
                record_audit(
                    Event.LOGIN_LOCKED,
                    actor=user,
                    success=False,
                    detail={
                        "reason": "too_many_failed_logins",
                        "locked_minutes": current_app.config["BLOGG_LOCKOUT_MINUTES"],
                    },
                )
            db.session.commit()
        return user, AUTH_INVALID

    # Password is correct from here on.
    if not user.active:
        if record:
            record_audit(
                failure_event, actor=user, success=False, detail={"reason": "account_disabled"}
            )
        return user, AUTH_DISABLED

    if user.is_locked:
        if record:
            record_audit(failure_event, actor=user, success=False, detail={"reason": "locked"})
        return user, AUTH_LOCKED

    if user.mfa_enabled and not user.verify_mfa_code(otp):
        if not user.mfa_secret or not otp:
            if record:
                record_audit(Event.MFA_CHALLENGE, actor=user, detail={"source": source})
            return user, AUTH_MFA_REQUIRED
        # A code was supplied but did not verify.
        if record:
            locked_now = user.record_failed_login()
            record_audit(
                Event.MFA_FAILED,
                actor=user,
                success=False,
                detail={"source": source, "failed_attempts": user.failed_login_attempts},
            )
            if locked_now:
                record_audit(
                    Event.LOGIN_LOCKED,
                    actor=user,
                    success=False,
                    detail={
                        "reason": "too_many_failed_mfa_attempts",
                        "locked_minutes": current_app.config["BLOGG_LOCKOUT_MINUTES"],
                    },
                )
            db.session.commit()
        return user, AUTH_MFA_FAILED

    # Full success (password + optional MFA).
    user.reset_login_failures()
    user.last_login_at = utc_now()
    db.session.add(user)
    if record:
        record_audit(success_event, actor=user, detail={"source": source})
    else:
        db.session.commit()
    return user, AUTH_OK


# ---------------------------------------------------------------------------
# Server-side sessions (revocation + idle/absolute timeouts)
# ---------------------------------------------------------------------------


def start_user_session(user, remember=False):
    """Log the user in via Flask-Login and register a server-side session."""
    login_user(user, remember=remember)
    jti = str(uuid.uuid4())
    now = utc_now()
    expires = now + timedelta(hours=current_app.config["BLOGG_SESSION_ABSOLUTE_HOURS"])
    row = UserSession(
        jti=jti,
        user_id=user.id,
        created_at=now,
        last_seen_at=now,
        expires_at=expires,
        ip=client_ip(),
        user_agent=client_user_agent(),
    )
    db.session.add(row)
    session["session_jti"] = jti
    record_audit(
        Event.SESSION_STARTED,
        actor=user,
        target_type="session",
        target_id=None,
        target_label=jti,
        detail={"remember": bool(remember)},
        commit=False,
    )
    db.session.commit()
    return jti


def end_user_session():
    """Revoke the current session and log out. Returns the jti revoked (or None)."""
    from flask_login import current_user

    actor = current_user._get_current_object() if current_user.is_authenticated else None
    jti = session.pop("session_jti", None)
    if jti:
        row = db.session.get(UserSession, jti)
        if row is not None and row.revoked_at is None:
            row.revoked_at = utc_now()
            db.session.add(row)
            record_audit(
                Event.SESSION_REVOKED,
                actor=actor,
                target_type="session",
                target_label=jti,
                commit=False,
            )
            db.session.commit()
    # Wipe every remaining key (csrf token, stale flashes) so the outgoing
    # cookie carries no identity or pre-logout state. Views flash *after*
    # calling this, so the final flash still lands in the cookie.
    session.clear()
    logout_user()
    return jti


def validate_current_session(user):
    """Enforce revocation/timeout for the authenticated browser session.

    Returns True when the session is usable (creating one if the Flask-Login
    remember-cookie re-authenticated without a session jti).
    """
    jti = session.get("session_jti")
    if not jti:
        # Remember-me re-authentication or pre-IAM session: establish a fresh one.
        start_user_session(user, remember=False)
        return True

    row = db.session.get(UserSession, jti)
    if row is None or row.user_id != user.id:
        session.pop("session_jti", None)
        start_user_session(user, remember=False)
        return True

    if row.revoked_at is not None:
        return False

    idle = current_app.config["BLOGG_SESSION_IDLE_MINUTES"]
    if row.is_expired(idle):
        row.revoked_at = utc_now()
        db.session.add(row)
        record_audit(
            Event.SESSION_EXPIRED,
            actor=user,
            target_type="session",
            target_label=jti,
            commit=False,
        )
        db.session.commit()
        return False

    # Throttled activity touch (avoid a write on every single request).
    now = utc_now()
    last_seen = as_naive_utc(row.last_seen_at)
    if last_seen is None or (as_naive_utc(now) - last_seen).total_seconds() > 60:
        row.last_seen_at = now
        db.session.add(row)
        db.session.commit()
    return True


def password_expired(user):
    """B2: opt-in password expiry via ``BLOGG_PASSWORD_MAX_AGE_DAYS`` (0 = off).

    True when the user's password is older than the configured maximum age.
    Falls back to ``member_since`` for accounts that never recorded a change
    (legacy rows), so enabling the policy doesn't instantly expire them all.
    """
    days = current_app.config.get("BLOGG_PASSWORD_MAX_AGE_DAYS", 0) or 0
    if days <= 0:
        return False
    changed = user.password_changed_at or user.member_since
    if changed is None:
        return False
    if changed.tzinfo is None:
        changed = changed.replace(tzinfo=timezone.utc)
    else:
        changed = changed.astimezone(timezone.utc)
    return utc_now() - changed > timedelta(days=days)


def revoke_user_sessions(user, keep_jti=None, event=Event.SESSION_REVOKED, detail=None):
    """Revoke every active session of a user (optionally keeping the current one).

    Also stamps the user's sessions_revoked_at cutoff (inside
    ``user.revoke_sessions``), which invalidates pre-revocation remember-me
    cookies — so the commit below runs even when no rows changed.
    """
    revoked = user.revoke_sessions(keep_jti=keep_jti)
    if revoked:
        record_audit(
            event,
            target_type="user",
            target_id=user.id,
            target_label=user.email,
            detail={"revoked": revoked, **(detail or {})},
            commit=False,
        )
    db.session.commit()
    return revoked


# ---------------------------------------------------------------------------
# MFA helpers (QR rendering)
# ---------------------------------------------------------------------------


def mfa_qr_data_uri(provisioning_uri):
    """Render an otpauth:// URI as an inline PNG data URI for the enrollment page."""
    image = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


# ---------------------------------------------------------------------------
# API tokens (opaque, revocable, scoped)
# ---------------------------------------------------------------------------


def validate_scopes(requested):
    """Split requested scope names into (valid, unknown)."""
    valid, unknown = [], []
    for scope in requested or []:
        scope = str(scope).strip()
        if not scope:
            continue
        if scope in ApiToken.KNOWN_SCOPES:
            if scope not in valid:
                valid.append(scope)
        elif scope not in unknown:
            unknown.append(scope)
    return valid, unknown


def issue_api_token(user, name=None, scopes=None, ttl=None):
    """Create an opaque API token. Returns ``(plaintext_token, ApiToken)``."""
    ttl = int(ttl or current_app.config["BLOGG_TOKEN_DEFAULT_TTL"])
    ttl = max(1, min(ttl, current_app.config["BLOGG_TOKEN_MAX_TTL"]))
    token = uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars, random & opaque
    row = ApiToken(
        user_id=user.id,
        name=(name or "default")[:64],
        token_hash=ApiToken.hash_token(token),
        scopes=" ".join(scopes or ApiToken.DEFAULT_SCOPES),
        created_at=utc_now(),
        expires_at=utc_now() + timedelta(seconds=ttl),
    )
    db.session.add(row)
    record_audit(
        Event.TOKEN_ISSUED,
        actor=user,
        target_type="token",
        target_id=None,
        target_label=row.name,
        detail={"scopes": row.scope_list, "ttl_seconds": ttl},
        commit=False,
    )
    db.session.commit()
    return token, row


def resolve_bearer_token(token):
    """Resolve an ``Authorization: Bearer`` value.

    Returns ``(user, token_row, error)``:
      - valid opaque token  -> (user, token_row, None)
      - legacy signed token -> (user, None, None)
      - invalid/expired/revoked -> (None, token_row|None, "reason string")
    """
    if not token:
        return None, None, "missing"

    row = ApiToken.query.filter_by(token_hash=ApiToken.hash_token(token)).first()
    if row is not None:
        if row.revoked_at is not None:
            return None, row, "revoked"
        if row.is_expired:
            return None, row, "expired"
        user = db.session.get(User, row.user_id)
        if user is None or not user.active:
            return None, row, "inactive"
        row.last_used_at = utc_now()
        db.session.add(row)
        db.session.commit()
        return user, row, None

    # Legacy signed token (kept for backwards compatibility; deprecated).
    user = User.verify_auth_token(token)
    if user is not None and user.active:
        return user, None, None
    return None, None, "invalid"

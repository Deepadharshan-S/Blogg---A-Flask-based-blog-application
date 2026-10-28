"""Self-service credential management: API tokens and login sessions."""

from flask import g, jsonify, session

from .. import db
from ..models import ApiToken, UserSession, utc_now
from ..security import Event, record_audit
from . import api
from .authentication import scope_required, token_auth_required
from .errors import forbidden, not_found


@api.route("/tokens", methods=["GET"])
@token_auth_required
@scope_required("tokens:manage")
def list_tokens():
    """List the calling user's API tokens (secrets are never returned)."""
    tokens = ApiToken.query.filter_by(user_id=g.current_user.id).order_by(
        ApiToken.created_at.desc()
    )
    return jsonify({"tokens": [t.to_json() for t in tokens]})


@api.route("/tokens/<int:id>", methods=["DELETE"])
@token_auth_required
@scope_required("tokens:manage")
def revoke_token(id):
    """Revoke one of your own API tokens immediately."""
    row = db.session.get(ApiToken, id)
    if row is None:
        return not_found(f"Token {id} not found")
    if row.user_id != g.current_user.id:
        return forbidden("You can only manage your own tokens.")
    if row.revoked_at is None:
        row.revoked_at = utc_now()
        db.session.add(row)
        record_audit(
            Event.TOKEN_REVOKED,
            actor=g.current_user,
            target_type="token",
            target_id=row.id,
            target_label=row.name,
            commit=False,
        )
        db.session.commit()
    return jsonify({"revoked": True, "token": row.to_json()})


@api.route("/me/sessions", methods=["GET"])
@token_auth_required
@scope_required("tokens:manage")
def list_sessions():
    """List your active login sessions/devices."""
    rows = (
        UserSession.query.filter_by(user_id=g.current_user.id, revoked_at=None)
        .order_by(UserSession.last_seen_at.desc())
        .all()
    )
    return jsonify(
        {"sessions": [r.to_json() for r in rows], "current_jti": session.get("session_jti")}
    )


@api.route("/me/sessions/<jti>", methods=["DELETE"])
@token_auth_required
@scope_required("tokens:manage")
def revoke_session(jti):
    """Revoke one of your own sessions by id."""
    row = db.session.get(UserSession, jti)
    if row is None or row.user_id != g.current_user.id:
        return not_found("Session not found")
    if row.revoked_at is None:
        row.revoked_at = utc_now()
        db.session.add(row)
        record_audit(
            Event.SESSION_REVOKED,
            actor=g.current_user,
            target_type="session",
            target_label=jti,
            commit=False,
        )
        db.session.commit()
    return jsonify({"revoked": True, "session": row.to_json()})


@api.route("/me/sessions", methods=["DELETE"])
@token_auth_required
@scope_required("tokens:manage")
def revoke_other_sessions():
    """Sign out every other device; the current browser session survives."""
    keep = session.get("session_jti")
    revoked = g.current_user.revoke_sessions(keep_jti=keep)
    if revoked:
        record_audit(
            Event.USER_SESSIONS_REVOKED,
            actor=g.current_user,
            detail={"revoked": revoked, "scope": "other_sessions"},
            commit=False,
        )
        db.session.commit()
    return jsonify({"revoked_count": revoked})


@api.route("/me/sessions/all", methods=["DELETE"])
@token_auth_required
@scope_required("tokens:manage")
def revoke_all_sessions():
    """Sign out everywhere: revoke every login session, including the current one."""
    revoked = g.current_user.revoke_sessions(keep_jti=None)
    if revoked:
        record_audit(
            Event.USER_SESSIONS_REVOKED,
            actor=g.current_user,
            detail={"revoked": revoked, "scope": "all_sessions"},
            commit=True,
        )
    return jsonify({"revoked_count": revoked})

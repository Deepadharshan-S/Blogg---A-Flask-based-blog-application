"""Admin REST API: user lifecycle, role/permission management and audit trail.

Every endpoint requires a valid token carrying the ``admin`` scope *and* the
matching RBAC permission on the owning account (defense in depth).
"""

from flask import current_app, g, jsonify, request
from sqlalchemy import and_, or_

from .. import db
from ..email import send_email
from ..models import AuditEvent, Permission, Role, User, utc_now
from ..security import (
    Event,
    administrator_count,
    record_audit,
    revoke_user_sessions,
)
from . import api
from .authentication import permission_required_api, scope_required, token_auth_required
from .errors import bad_request

BUILTIN_ROLES = Role.BUILTIN_NAMES


def _pagination():
    page = request.args.get("page", 1, type=int)
    per_page = min(
        request.args.get("per_page", current_app.config["BLOGG_ADMIN_PER_PAGE"], type=int),
        100,
    )
    return max(1, page), max(1, per_page)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@api.route("/admin/users", methods=["GET"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.MANAGE_USERS)
def admin_list_users():
    """Search/filter accounts: ``?q=`` ``?role=`` ``?status=`` ``?page=``."""
    query = User.query
    q = request.args.get("q", "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(User.username.ilike(like), User.email.ilike(like), User.name.ilike(like))
        )
    role = request.args.get("role", "").strip()
    if role:
        query = query.join(Role).filter(Role.name == role)
    status = request.args.get("status", "").strip()
    if status == "disabled":
        query = query.filter(User.active.is_(False))
    elif status == "active":
        query = query.filter(User.active.is_(True))
    elif status == "locked":
        query = query.filter(User.locked_until > utc_now())
    elif status == "unconfirmed":
        query = query.filter(User.confirmed.is_(False))

    page, per_page = _pagination()
    pagination = query.order_by(User.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify(
        {
            "users": [u.to_admin_json() for u in pagination.items],
            "total": pagination.total,
            "pages": pagination.pages,
            "current_page": pagination.page,
        }
    )


@api.route("/admin/users/<int:id>", methods=["GET"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.MANAGE_USERS)
def admin_get_user(id):
    user = db.get_or_404(User, id)
    events = (
        AuditEvent.query.filter(
            or_(
                AuditEvent.actor_id == user.id,
                and_(AuditEvent.target_type == "user", AuditEvent.target_id == user.id),
            )
        )
        .order_by(AuditEvent.timestamp.desc())
        .limit(20)
        .all()
    )
    return jsonify({"user": user.to_admin_json(), "audit": [e.to_json() for e in events]})


@api.route("/admin/users/<int:id>", methods=["PATCH"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.MANAGE_USERS)
def admin_update_user(id):
    """Change role / enabled state / confirmation state of an account."""
    user = db.get_or_404(User, id)
    actor = g.current_user
    data = request.get_json(silent=True) or {}
    if not data:
        return bad_request("No changes requested.")
    if user.deleted_at:
        return bad_request("This account has been deleted.")

    changes = {}

    if "role" in data:
        role_name = data.get("role")
        role = Role.query.filter_by(name=role_name).first() if role_name else None
        if role is None:
            return bad_request(f"Unknown role: {role_name}")
        if user.id == g.current_user.id:
            return bad_request("Use another administrator account to change your own role.")
        old_role = user.role.name if user.role else None
        if old_role != role.name:
            # Last-administrator protection.
            removes_admin = (
                user.can(Permission.ADMIN)
                and not role.permissions & Permission.ADMIN == Permission.ADMIN
            )
            if removes_admin and administrator_count() <= 1:
                return bad_request("Cannot demote the last administrator.")
            user.role = role
            changes["role"] = {"from": old_role, "to": role.name}
            record_audit(
                Event.USER_ROLE_CHANGED,
                actor=actor,
                target_type="user",
                target_id=user.id,
                target_label=user.email,
                detail={"from": old_role, "to": role.name},
                commit=False,
            )

    if "active" in data:
        new_active = bool(data["active"])
        if new_active != bool(user.active):
            if not new_active and user.id == g.current_user.id:
                return bad_request("You cannot disable your own account.")
            if user.can(Permission.ADMIN) and not new_active and administrator_count() <= 1:
                return bad_request("Cannot disable the last administrator.")
            user.active = new_active
            changes["active"] = new_active
            if not new_active:
                user.revoke_sessions()
                event = Event.USER_DISABLED
            else:
                user.reset_login_failures()
                event = Event.USER_ENABLED
            record_audit(
                event,
                actor=actor,
                target_type="user",
                target_id=user.id,
                target_label=user.email,
                commit=False,
            )

    if "confirmed" in data:
        new_confirmed = bool(data["confirmed"])
        if new_confirmed != bool(user.confirmed):
            user.confirmed = new_confirmed
            changes["confirmed"] = new_confirmed
            record_audit(
                Event.USER_CONFIRMED,
                actor=actor,
                target_type="user",
                target_id=user.id,
                target_label=user.email,
                detail={"confirmed": new_confirmed},
                commit=False,
            )

    if "must_change_password" in data:
        new_flag = bool(data["must_change_password"])
        if new_flag != bool(user.must_change_password):
            user.must_change_password = new_flag
            changes["must_change_password"] = new_flag
            record_audit(
                Event.USER_PASSWORD_CHANGE_REQUIRED,
                actor=actor,
                target_type="user",
                target_id=user.id,
                target_label=user.email,
                detail={"action": "required" if new_flag else "cleared"},
                commit=False,
            )

    if not changes:
        return jsonify({"changed": False, "user": user.to_admin_json()})

    db.session.add(user)
    db.session.commit()
    return jsonify({"changed": True, "changes": changes, "user": user.to_admin_json()})


@api.route("/admin/users/<int:id>/unlock", methods=["POST"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.MANAGE_USERS)
def admin_unlock_user(id):
    user = db.get_or_404(User, id)
    was_locked = user.is_locked
    user.unlock()
    db.session.add(user)
    if was_locked:
        record_audit(
            Event.USER_UNLOCKED,
            actor=g.current_user,
            target_type="user",
            target_id=user.id,
            target_label=user.email,
            commit=False,
        )
    db.session.commit()
    return jsonify({"unlocked": was_locked, "user": user.to_admin_json()})


@api.route("/admin/users/<int:id>/sessions", methods=["DELETE"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.MANAGE_USERS)
def admin_revoke_sessions(id):
    user = db.get_or_404(User, id)
    revoked = revoke_user_sessions(
        user, detail={"by": g.current_user.email, "reason": "admin_action"}
    )
    return jsonify({"revoked_count": revoked})


@api.route("/admin/users/<int:id>/mfa", methods=["DELETE"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.MANAGE_USERS)
def admin_reset_mfa(id):
    """Reset (disable) MFA for a user who lost their device."""
    user = db.get_or_404(User, id)
    user.disable_mfa()
    db.session.add(user)
    record_audit(
        Event.USER_MFA_RESET,
        actor=g.current_user,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        commit=False,
    )
    db.session.commit()
    return jsonify({"mfa_enabled": False, "user": user.to_admin_json()})


@api.route("/admin/users/<int:id>/password-reset", methods=["POST"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.MANAGE_USERS)
def admin_send_password_reset(id):
    user = db.get_or_404(User, id)
    token = user.generate_reset_token()
    send_email(
        user.email,
        "Reset Your Password",
        "auth/email/reset_password",
        user=user,
        token=token,
    )
    record_audit(
        Event.USER_PASSWORD_RESET_SENT,
        actor=g.current_user,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        commit=False,
    )
    db.session.commit()
    return jsonify({"sent": True, "email": user.email})


@api.route("/admin/users/<int:id>", methods=["DELETE"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.MANAGE_USERS)
def admin_delete_user(id):
    """Tombstone an account: anonymize it, keep its posts, revoke everything."""
    user = db.get_or_404(User, id)
    if user.id == g.current_user.id:
        return bad_request("Use your account's security page to delete yourself.")
    if user.deleted_at:
        return bad_request("This account has already been deleted.")
    if user.can(Permission.ADMIN) and administrator_count() <= 1:
        return bad_request("Cannot delete the last administrator.")
    user.revoke_sessions()
    user.anonymize()
    record_audit(
        Event.USER_DELETED,
        actor=g.current_user,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        detail={"method": "api"},
        commit=False,
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"deleted": True, "user": user.to_admin_json()})


# ---------------------------------------------------------------------------
# Roles & permissions
# ---------------------------------------------------------------------------


@api.route("/admin/roles", methods=["GET"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.ADMIN)
def admin_list_roles():
    roles = Role.query.order_by(Role.id).all()
    return jsonify({"roles": [r.to_json() for r in roles], "permissions": Permission.all()})


@api.route("/admin/roles", methods=["POST"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.ADMIN)
def admin_create_role():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name or len(name) > 64:
        return bad_request("Role name is required (max 64 characters).")
    if Role.query.filter_by(name=name).first() is not None:
        return bad_request(f"Role '{name}' already exists.")
    try:
        permissions = Role.permission_value(data.get("permissions") or [])
    except ValueError as exc:
        return bad_request(str(exc))

    role = Role(name=name, permissions=permissions, default=False)
    db.session.add(role)
    record_audit(
        Event.ROLE_CREATED,
        actor=g.current_user,
        target_type="role",
        target_label=name,
        detail={"permissions": Role.permission_names(permissions)},
        commit=False,
    )
    db.session.commit()
    response = jsonify({"role": role.to_json()})
    response.status_code = 201
    return response


@api.route("/admin/roles/<int:id>", methods=["PATCH"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.ADMIN)
def admin_update_role(id):
    role = db.get_or_404(Role, id)
    data = request.get_json(silent=True) or {}
    if not data:
        return bad_request("No changes requested.")
    if role.name in BUILTIN_ROLES and "name" in data and data["name"] != role.name:
        return bad_request("Built-in roles cannot be renamed.")

    detail = {}
    if "name" in data:
        new_name = (data.get("name") or "").strip()
        if not new_name or len(new_name) > 64:
            return bad_request("Role name is required (max 64 characters).")
        existing = Role.query.filter_by(name=new_name).first()
        if existing is not None and existing.id != role.id:
            return bad_request(f"Role '{new_name}' already exists.")
        detail["name"] = {"from": role.name, "to": new_name}
        role.name = new_name

    if "permissions" in data:
        try:
            permissions = Role.permission_value(data.get("permissions") or [])
        except ValueError as exc:
            return bad_request(str(exc))
        loses_admin = (
            role.permissions & Permission.ADMIN == Permission.ADMIN
            and permissions & Permission.ADMIN != Permission.ADMIN
        )
        if loses_admin and role.user_count > 0 and administrator_count() <= 1:
            return bad_request("Cannot remove the ADMIN permission from the last administrator.")
        detail["permissions"] = {
            "from": Role.permission_names(role.permissions),
            "to": Role.permission_names(permissions),
        }
        role.permissions = permissions

    db.session.add(role)
    record_audit(
        Event.ROLE_UPDATED,
        actor=g.current_user,
        target_type="role",
        target_id=role.id,
        target_label=role.name,
        detail=detail,
        commit=False,
    )
    db.session.commit()
    return jsonify({"changed": True, "role": role.to_json()})


@api.route("/admin/roles/<int:id>", methods=["DELETE"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.ADMIN)
def admin_delete_role(id):
    role = db.get_or_404(Role, id)
    if role.name in BUILTIN_ROLES:
        return bad_request("Built-in roles cannot be deleted.")
    if role.user_count > 0:
        return bad_request("Reassign users away from this role before deleting it.")
    if role.default:
        return bad_request("The default role cannot be deleted.")
    name = role.name
    db.session.delete(role)
    record_audit(
        Event.ROLE_DELETED,
        actor=g.current_user,
        target_type="role",
        target_label=name,
        commit=False,
    )
    db.session.commit()
    return jsonify({"deleted": True, "role": name})


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


@api.route("/admin/audit", methods=["GET"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.VIEW_AUDIT)
def admin_audit_log():
    """Security event log: ``?event=`` ``?success=`` ``?q=`` ``?page=``."""
    query = AuditEvent.query
    event = request.args.get("event", "").strip()
    if event:
        query = query.filter(AuditEvent.event == event)
    success = request.args.get("success", "").strip()
    if success in ("0", "1", "true", "false"):
        want = success in ("1", "true")
        query = query.filter(AuditEvent.success.is_(want))
    q = request.args.get("q", "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(AuditEvent.actor_label.ilike(like), AuditEvent.target_label.ilike(like))
        )

    page, per_page = _pagination()
    pagination = query.order_by(AuditEvent.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify(
        {
            "events": [e.to_json() for e in pagination.items],
            "total": pagination.total,
            "pages": pagination.pages,
            "current_page": pagination.page,
        }
    )


@api.route("/admin/audit/event-names", methods=["GET"])
@token_auth_required
@scope_required("admin")
@permission_required_api(Permission.VIEW_AUDIT)
def admin_audit_event_names():
    rows = db.session.query(AuditEvent.event).distinct().order_by(AuditEvent.event).all()
    return jsonify({"events": [r[0] for r in rows]})

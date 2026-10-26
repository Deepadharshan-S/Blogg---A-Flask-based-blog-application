"""Admin console: dashboard, user lifecycle, role/permission and audit views."""

import csv
import io
import json

from flask import Response, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import and_, or_

from .. import db
from ..decorators import audit_required, manage_users_required
from ..email import send_email
from ..models import (
    AccessLog,
    ApiToken,
    AuditEvent,
    Permission,
    Post,
    Role,
    User,
    UserSession,
    utc_now,
)
from ..security import (
    Event,
    active_administrator_count,
    administrator_count,
    escape_like,
    record_audit,
    revoke_user_sessions,
)
from . import admin
from .forms import RoleForm, UserFilterForm


def _page():
    return max(1, request.args.get("page", 1, type=int))


def _per_page(config_key):
    return max(1, request.args.get("page_size", current_app.config[config_key], type=int))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@admin.route("/")
@login_required
@manage_users_required
def dashboard():
    stats = {
        "users": User.query.count(),
        "disabled": User.query.filter_by(active=False).count(),
        "locked": User.query.filter(User.locked_until > utc_now()).count(),
        "unconfirmed": User.query.filter_by(confirmed=False).count(),
        "administrators": administrator_count(),
        "roles": Role.query.count(),
        "posts": Post.query.count(),
        "active_sessions": UserSession.query.filter_by(revoked_at=None).count(),
        "issued_tokens": ApiToken.query.filter_by(revoked_at=None).count(),
        "audit_events": AuditEvent.query.count(),
        "access_logs": AccessLog.query.count(),
    }
    recent = AuditEvent.query.order_by(AuditEvent.timestamp.desc()).limit(12).all()
    return render_template("admin/dashboard.html", stats=stats, recent=recent)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@admin.route("/users")
@login_required
@manage_users_required
def users():
    form = UserFilterForm(request.args)
    form.role.choices = [("", "All roles")] + [
        (r.name, r.name) for r in Role.query.order_by(Role.name).all()
    ]

    query = User.query
    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{escape_like(q)}%"
        query = query.filter(
            or_(
                User.username.ilike(like, escape="\\"),
                User.email.ilike(like, escape="\\"),
                User.name.ilike(like, escape="\\"),
            )
        )
    role = (request.args.get("role") or "").strip()
    if role:
        query = query.join(Role).filter(Role.name == role)
    status = (request.args.get("status") or "").strip()
    if status == "disabled":
        query = query.filter(User.active.is_(False))
    elif status == "active":
        query = query.filter(User.active.is_(True))
    elif status == "locked":
        query = query.filter(User.locked_until > utc_now())
    elif status == "unconfirmed":
        query = query.filter(User.confirmed.is_(False))

    page = _page()
    pagination = query.order_by(User.id.desc()).paginate(
        page=page, per_page=_per_page("BLOGG_ADMIN_PER_PAGE"), error_out=False
    )
    return render_template(
        "admin/users.html", form=form, users=pagination.items, pagination=pagination, page=page
    )


@admin.route("/users/<int:id>", methods=["GET", "POST"])
@login_required
@manage_users_required
def user_detail(id):
    user = db.get_or_404(User, id)
    actor = current_user._get_current_object()

    if request.method == "POST":
        action = request.form.get("action", "")

        if user.deleted_at:
            flash("This account has been deleted; no further actions are possible.", "error")
            return redirect(url_for("admin.user_detail", id=id))

        if action == "role":
            role = db.session.get(Role, request.form.get("role_id", type=int))
            if role is None:
                flash("Unknown role.", "error")
            elif user == actor:
                flash("Use another administrator account to change your own role.", "error")
            elif role.has_admin and not actor.can(Permission.ADMIN):
                # A MANAGE_USERS-only operator must not be able to mint a new
                # administrator (privilege escalation).
                flash("Only administrators can grant the Administrator permission.", "error")
            elif (
                user.active
                and user.can(Permission.ADMIN)
                and not role.has_admin
                and active_administrator_count(exclude_user_id=user.id) == 0
            ):
                flash("Cannot demote the last administrator.", "error")
            else:
                old_role = user.role.name if user.role else None
                user.role = role
                record_audit(
                    Event.USER_ROLE_CHANGED,
                    actor=actor,
                    target_type="user",
                    target_id=user.id,
                    target_label=user.email,
                    detail={"from": old_role, "to": role.name, "via": "admin_console"},
                    commit=False,
                )
                db.session.commit()
                flash(f"{user.username} is now {role.name}.", "success")

        elif action == "toggle_active":
            if user == actor:
                flash("You cannot disable your own account.", "error")
            elif (
                user.active
                and user.can(Permission.ADMIN)
                and active_administrator_count(exclude_user_id=user.id) == 0
            ):
                flash("Cannot disable the last administrator.", "error")
            else:
                user.active = not user.active
                if user.active:
                    user.reset_login_failures()
                    event = Event.USER_ENABLED
                    message = "Account enabled."
                    category = "success"
                else:
                    user.revoke_sessions()
                    event = Event.USER_DISABLED
                    message = "Account disabled and sessions revoked."
                    category = "success"
                record_audit(
                    event,
                    actor=actor,
                    target_type="user",
                    target_id=user.id,
                    target_label=user.email,
                    commit=False,
                )
                db.session.commit()
                flash(message, category)

        elif action == "unlock":
            was_locked = user.is_locked
            user.unlock()
            db.session.add(user)
            if was_locked:
                record_audit(
                    Event.USER_UNLOCKED,
                    actor=actor,
                    target_type="user",
                    target_id=user.id,
                    target_label=user.email,
                    commit=False,
                )
            db.session.commit()
            if was_locked:
                flash("Account unlocked.", "success")
            else:
                flash("Account was not locked.", "info")

        elif action == "confirm":
            user.confirmed = True
            db.session.add(user)
            record_audit(
                Event.USER_CONFIRMED,
                actor=actor,
                target_type="user",
                target_id=user.id,
                target_label=user.email,
                detail={"confirmed": True, "via": "admin_console"},
                commit=False,
            )
            db.session.commit()
            flash("Account marked as confirmed.", "success")

        elif action == "revoke_sessions":
            revoked = revoke_user_sessions(
                user, detail={"by": actor.email, "reason": "admin_console"}
            )
            flash(f"Revoked {revoked} session(s).", "success")

        elif action == "force_password_change":
            user.must_change_password = not user.must_change_password
            required = user.must_change_password
            db.session.add(user)
            record_audit(
                Event.USER_PASSWORD_CHANGE_REQUIRED,
                actor=actor,
                target_type="user",
                target_id=user.id,
                target_label=user.email,
                detail={"action": "required" if required else "cleared"},
                commit=False,
            )
            db.session.commit()
            flash(
                "User must change their password at next sign-in."
                if required
                else "Forced password change cleared.",
                "success",
            )

        elif action == "delete_user":
            if user == actor:
                flash("You cannot delete your own account here; use your security page.", "error")
            elif (
                user.active
                and user.can(Permission.ADMIN)
                and active_administrator_count(exclude_user_id=user.id) == 0
            ):
                flash("Cannot delete the last administrator.", "error")
            else:
                user.revoke_sessions()
                user.anonymize()
                record_audit(
                    Event.USER_DELETED,
                    actor=actor,
                    target_type="user",
                    target_id=user.id,
                    target_label=user.email,
                    detail={"method": "admin_console"},
                    commit=False,
                )
                db.session.commit()
                flash(
                    "Account deleted; their posts remain under an anonymous tombstone.",
                    "success",
                )

        elif action == "reset_mfa":
            user.disable_mfa()
            db.session.add(user)
            record_audit(
                Event.USER_MFA_RESET,
                actor=actor,
                target_type="user",
                target_id=user.id,
                target_label=user.email,
                commit=False,
            )
            db.session.commit()
            flash("Two-factor authentication has been reset for this user.", "success")

        elif action == "send_reset":
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
                actor=actor,
                target_type="user",
                target_id=user.id,
                target_label=user.email,
                commit=False,
            )
            db.session.commit()
            flash(f"Password reset email sent to {user.email}.", "success")

        else:
            flash("Unknown action.", "error")

        return redirect(url_for("admin.user_detail", id=user.id))

    sessions = (
        UserSession.query.filter_by(user_id=user.id, revoked_at=None)
        .order_by(UserSession.last_seen_at.desc())
        .limit(10)
        .all()
    )
    events = (
        AuditEvent.query.filter(
            or_(
                AuditEvent.actor_id == user.id,
                and_(AuditEvent.target_type == "user", AuditEvent.target_id == user.id),
            )
        )
        .order_by(AuditEvent.timestamp.desc())
        .limit(15)
        .all()
    )
    return render_template(
        "admin/user_detail.html",
        user=user,
        roles=Role.query.order_by(Role.name).all(),
        sessions=sessions,
        events=events,
        is_locked=user.is_locked,
    )


# ---------------------------------------------------------------------------
# Roles & permissions
# ---------------------------------------------------------------------------


@admin.route("/roles")
@login_required
def roles():
    if not (current_user.can(Permission.MANAGE_USERS) or current_user.can(Permission.ADMIN)):
        abort(403)
    return render_template("admin/roles.html", roles=Role.query.order_by(Role.id).all())


@admin.route("/roles/new", methods=["GET", "POST"])
@login_required
def role_new():
    if not current_user.can(Permission.ADMIN):
        abort(403)
    form = RoleForm()
    if form.validate_on_submit():
        name = form.name.data.strip()
        if Role.query.filter_by(name=name).first() is not None:
            flash(f"Role '{name}' already exists.", "error")
            return redirect(url_for("admin.role_new"))
        role = Role(
            name=name, permissions=Role.permission_value(form.permission_names()), default=False
        )
        db.session.add(role)
        record_audit(
            Event.ROLE_CREATED,
            actor=current_user._get_current_object(),
            target_type="role",
            target_label=name,
            detail={"permissions": form.permission_names()},
            commit=False,
        )
        db.session.commit()
        flash(f"Role '{name}' created.", "success")
        return redirect(url_for("admin.roles"))
    return render_template("admin/role_form.html", form=form, title="New Role", role=None)


@admin.route("/roles/<int:id>/edit", methods=["GET", "POST"])
@login_required
def role_edit(id):
    if not current_user.can(Permission.ADMIN):
        abort(403)
    role = db.get_or_404(Role, id)
    form = RoleForm()
    if form.validate_on_submit():
        new_name = form.name.data.strip()
        if role.is_builtin and new_name != role.name:
            flash("Built-in roles cannot be renamed.", "error")
            return redirect(url_for("admin.role_edit", id=role.id))
        if new_name != role.name and Role.query.filter_by(name=new_name).first() is not None:
            flash(f"Role '{new_name}' already exists.", "error")
            return redirect(url_for("admin.role_edit", id=role.id))
        permissions = Role.permission_value(form.permission_names())
        loses_admin = role.has_admin and not permissions & Permission.ADMIN
        # Only an *active* administrator elsewhere can absorb this role losing
        # the ADMIN permission; counting disabled accounts (or this role's own
        # holders) would allow zeroing out the administrators.
        if (
            loses_admin
            and role.user_count > 0
            and active_administrator_count(exclude_role_id=role.id) == 0
        ):
            flash("Cannot remove the ADMIN permission from the last administrator role.", "error")
            return redirect(url_for("admin.role_edit", id=role.id))
        detail = {"name": new_name, "permissions": form.permission_names()}
        if new_name != role.name:
            detail["old_name"] = role.name
        role.name = new_name
        role.permissions = permissions
        db.session.add(role)
        record_audit(
            Event.ROLE_UPDATED,
            actor=current_user._get_current_object(),
            target_type="role",
            target_id=role.id,
            target_label=role.name,
            detail=detail,
            commit=False,
        )
        db.session.commit()
        flash(f"Role '{role.name}' updated.", "success")
        return redirect(url_for("admin.roles"))
    elif request.method == "GET":
        form.name.data = role.name
        form.load_permissions(role.permissions)
    return render_template("admin/role_form.html", form=form, title="Edit Role", role=role)


@admin.route("/roles/<int:id>/delete", methods=["POST"])
@login_required
def role_delete(id):
    if not current_user.can(Permission.ADMIN):
        abort(403)
    role = db.get_or_404(Role, id)
    if role.is_builtin:
        flash("Built-in roles cannot be deleted.", "error")
    elif role.user_count > 0:
        flash("Reassign users away from this role before deleting it.", "error")
    elif role.default:
        flash("The default role cannot be deleted.", "error")
    else:
        name = role.name
        db.session.delete(role)
        record_audit(
            Event.ROLE_DELETED,
            actor=current_user._get_current_object(),
            target_type="role",
            target_label=name,
            commit=False,
        )
        db.session.commit()
        flash(f"Role '{name}' deleted.", "success")
    return redirect(url_for("admin.roles"))


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

_AUDIT_EXPORT_COLUMNS = (
    "id",
    "timestamp",
    "event",
    "actor",
    "target_type",
    "target_id",
    "target",
    "success",
    "ip",
    "user_agent",
    "detail",
)


def _audit_filters():
    """Active audit-log filters (shared by the console view and the export)."""
    return {
        "event": (request.args.get("event") or "").strip(),
        "success": (request.args.get("success") or "").strip(),
        "q": (request.args.get("q") or "").strip(),
    }


def _filtered_audit_query():
    filters = _audit_filters()
    query = AuditEvent.query
    if filters["event"]:
        query = query.filter(AuditEvent.event == filters["event"])
    if filters["success"] in ("0", "1"):
        query = query.filter(AuditEvent.success.is_(filters["success"] == "1"))
    if filters["q"]:
        like = f"%{escape_like(filters['q'])}%"
        query = query.filter(
            or_(
                AuditEvent.actor_label.ilike(like, escape="\\"),
                AuditEvent.target_label.ilike(like, escape="\\"),
            )
        )
    return query


@admin.route("/audit")
@login_required
@audit_required
def audit_log():
    # Reading the audit trail is itself an auditable action: record it before
    # running the query so the viewer sees their own access on the page.
    record_audit(
        Event.AUDIT_VIEWED,
        actor=current_user._get_current_object(),
        detail={"filters": _audit_filters()},
    )
    query = _filtered_audit_query()

    page = _page()
    pagination = query.order_by(AuditEvent.timestamp.desc()).paginate(
        page=page, per_page=_per_page("BLOGG_AUDIT_PER_PAGE"), error_out=False
    )
    event_names = [r[0] for r in db.session.query(AuditEvent.event).distinct().all()]
    return render_template(
        "admin/audit.html",
        events=pagination.items,
        pagination=pagination,
        page=page,
        event_names=sorted(event_names),
        filters=_audit_filters(),
    )


@admin.route("/audit/export")
@login_required
@audit_required
def audit_export():
    """Download the (filtered) audit trail as CSV or JSON."""
    fmt = (request.args.get("format") or "csv").strip().lower()
    if fmt not in ("csv", "json"):
        abort(400)

    query = _filtered_audit_query()
    rows = query.order_by(AuditEvent.timestamp.desc()).all()
    filters = _audit_filters()
    record_audit(
        Event.AUDIT_EXPORTED,
        actor=current_user._get_current_object(),
        detail={"format": fmt, "count": len(rows), "filters": filters},
    )

    if fmt == "json":
        payload = json.dumps(
            {
                "exported_at": utc_now().isoformat(),
                "filters": filters,
                "count": len(rows),
                "events": [row.to_json() for row in rows],
            },
            indent=2,
        )
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": 'attachment; filename="audit-log.json"'},
        )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_AUDIT_EXPORT_COLUMNS)
    for row in rows:
        writer.writerow(
            [
                row.id,
                row.timestamp.isoformat() if row.timestamp else "",
                row.event,
                row.actor_label or "",
                row.target_type or "",
                row.target_id if row.target_id is not None else "",
                row.target_label or "",
                int(bool(row.success)),
                row.ip or "",
                row.user_agent or "",
                row.detail or "",
            ]
        )
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="audit-log.csv"'},
    )


# ---------------------------------------------------------------------------
# Access log (per-request trail)
# ---------------------------------------------------------------------------


def _access_filters():
    """Active access-log filters (shared by the console view and the API)."""
    return {
        "q": (request.args.get("q") or "").strip(),
        "method": (request.args.get("method") or "").strip().upper(),
        "status": (request.args.get("status") or "").strip().lower(),
    }


def _filtered_access_query(filters=None):
    filters = filters if filters is not None else _access_filters()
    query = AccessLog.query
    if filters["q"]:
        like = f"%{escape_like(filters['q'])}%"
        query = query.filter(
            or_(
                AccessLog.path.ilike(like, escape="\\"),
                AccessLog.user_label.ilike(like, escape="\\"),
                AccessLog.ip.ilike(like, escape="\\"),
            )
        )
    if filters["method"]:
        query = query.filter(AccessLog.method == filters["method"])
    if filters["status"] in AccessLog.STATUS_CLASSES:
        low = int(filters["status"][0]) * 100
        query = query.filter(AccessLog.status_code >= low, AccessLog.status_code < low + 100)
    else:
        filters["status"] = ""
    return query


@admin.route("/access-logs")
@login_required
@audit_required
def access_log():
    filters = _access_filters()
    # Who read the access trail is auditable, exactly like the audit trail.
    record_audit(
        Event.ACCESS_LOG_VIEWED,
        actor=current_user._get_current_object(),
        detail={"filters": filters},
    )
    query = _filtered_access_query(filters)

    page = _page()
    pagination = query.order_by(AccessLog.timestamp.desc()).paginate(
        page=page, per_page=_per_page("BLOGG_ACCESS_LOG_PER_PAGE"), error_out=False
    )
    return render_template(
        "admin/access_logs.html",
        logs=pagination.items,
        pagination=pagination,
        page=page,
        filters=filters,
    )

"""Admin console: dashboard, user lifecycle, role/permission and audit views."""

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import and_, or_

from .. import db
from ..decorators import audit_required, manage_users_required
from ..email import send_email
from ..models import (
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
    administrator_count,
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
        like = f"%{q}%"
        query = query.filter(
            or_(User.username.ilike(like), User.email.ilike(like), User.name.ilike(like))
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
            flash("This account has been deleted; no further actions are possible.")
            return redirect(url_for("admin.user_detail", id=id))

        if action == "role":
            role = db.session.get(Role, request.form.get("role_id", type=int))
            if role is None:
                flash("Unknown role.")
            elif user == actor:
                flash("Use another administrator account to change your own role.")
            elif user.can(Permission.ADMIN) and not role.has_admin and administrator_count() <= 1:
                flash("Cannot demote the last administrator.")
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
                flash(f"{user.username} is now {role.name}.")

        elif action == "toggle_active":
            if user == actor:
                flash("You cannot disable your own account.")
            elif user.active and user.can(Permission.ADMIN) and administrator_count() <= 1:
                flash("Cannot disable the last administrator.")
            else:
                user.active = not user.active
                if user.active:
                    user.reset_login_failures()
                    event = Event.USER_ENABLED
                    message = "Account enabled."
                else:
                    user.revoke_sessions()
                    event = Event.USER_DISABLED
                    message = "Account disabled and sessions revoked."
                record_audit(
                    event,
                    actor=actor,
                    target_type="user",
                    target_id=user.id,
                    target_label=user.email,
                    commit=False,
                )
                db.session.commit()
                flash(message)

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
            flash("Account unlocked." if was_locked else "Account was not locked.")

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
            flash("Account marked as confirmed.")

        elif action == "revoke_sessions":
            revoked = revoke_user_sessions(
                user, detail={"by": actor.email, "reason": "admin_console"}
            )
            flash(f"Revoked {revoked} session(s).")

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
                else "Forced password change cleared."
            )

        elif action == "delete_user":
            if user == actor:
                flash("You cannot delete your own account here; use your security page.")
            elif user.can(Permission.ADMIN) and administrator_count() <= 1:
                flash("Cannot delete the last administrator.")
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
                flash("Account deleted; their posts remain under an anonymous tombstone.")

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
            flash("Two-factor authentication has been reset for this user.")

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
            flash(f"Password reset email sent to {user.email}.")

        else:
            flash("Unknown action.")

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
            flash(f"Role '{name}' already exists.")
        else:
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
            flash(f"Role '{name}' created.")
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
            flash("Built-in roles cannot be renamed.")
        elif new_name != role.name and Role.query.filter_by(name=new_name).first() is not None:
            flash(f"Role '{new_name}' already exists.")
        else:
            permissions = Role.permission_value(form.permission_names())
            loses_admin = role.has_admin and not permissions & Permission.ADMIN
            if loses_admin and role.user_count > 0 and administrator_count() <= 1:
                flash("Cannot remove the ADMIN permission from the last administrator.")
            else:
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
                flash(f"Role '{role.name}' updated.")
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
        flash("Built-in roles cannot be deleted.")
    elif role.user_count > 0:
        flash("Reassign users away from this role before deleting it.")
    elif role.default:
        flash("The default role cannot be deleted.")
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
        flash(f"Role '{name}' deleted.")
    return redirect(url_for("admin.roles"))


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


@admin.route("/audit")
@login_required
@audit_required
def audit_log():
    query = AuditEvent.query
    event = (request.args.get("event") or "").strip()
    if event:
        query = query.filter(AuditEvent.event == event)
    success = (request.args.get("success") or "").strip()
    if success in ("0", "1"):
        query = query.filter(AuditEvent.success.is_(success == "1"))
    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(AuditEvent.actor_label.ilike(like), AuditEvent.target_label.ilike(like))
        )

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
        filters={"event": event, "success": success, "q": q},
    )

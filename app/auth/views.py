from urllib.parse import urlsplit

from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required

from .. import db, limiter
from ..email import send_email
from ..models import Permission, User, UserSession, utc_now
from ..security import (
    AUTH_DISABLED,
    AUTH_LOCKED,
    AUTH_MFA_FAILED,
    AUTH_MFA_REQUIRED,
    AUTH_OK,
    Event,
    active_administrator_count,
    authenticate_credentials,
    end_user_session,
    mfa_qr_data_uri,
    password_expired,
    record_audit,
    revoke_user_sessions,
    start_user_session,
    validate_current_session,
)
from . import auth
from .forms import (
    ChangeEmailForm,
    ChangePasswordForm,
    DisableMFAForm,
    LoginForm,
    MFAVerificationForm,
    PasswordResetForm,
    PasswordResetRequestForm,
    RegistrationForm,
)


def is_safe_url(target):
    """Validate that a redirect target is a safe local relative path."""
    if not target or not isinstance(target, str):
        return False
    target = target.strip()
    if target.startswith("//") or target.startswith("/\\") or target.startswith("\\"):
        return False
    try:
        parsed = urlsplit(target)
    except ValueError:
        return False
    if parsed.scheme or parsed.netloc:
        return False
    if not target.startswith("/"):
        return False
    return True


def _login_rate_limit():
    return current_app.config.get("BLOGG_LOGIN_RATE_LIMIT", "5 per minute")


def _post_login_redirect():
    next_url = request.args.get("next")
    if not is_safe_url(next_url):
        next_url = url_for("main.index")
    return next_url


@auth.route("/login", methods=["GET", "POST"])
@limiter.limit(_login_rate_limit)
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user, status = authenticate_credentials(form.email.data, form.password.data)
        if status == AUTH_OK:
            start_user_session(user, remember=form.remember_me.data)
            current_app.logger.info(f"User logged in: {user.email}")
            if user.must_change_password:
                flash("You must change your password before continuing.", "warning")
                return redirect(url_for("auth.change_password"))
            if password_expired(user):
                flash("Your password has expired. Please choose a new one.", "warning")
                return redirect(url_for("auth.change_password"))
            return redirect(_post_login_redirect())

        current_app.logger.warning(f"Failed login attempt: {form.email.data}")
        if status == AUTH_MFA_REQUIRED:
            session["mfa_user_id"] = user.id
            session["mfa_remember"] = bool(form.remember_me.data)
            session["mfa_next"] = request.args.get("next")
            return redirect(url_for("auth.mfa"))
        if status == AUTH_DISABLED:
            flash("Your account has been disabled. Contact an administrator.", "error")
        elif status == AUTH_LOCKED:
            minutes = current_app.config["BLOGG_LOCKOUT_MINUTES"]
            flash(
                "Your account is temporarily locked due to repeated failed login attempts. "
                f"Please try again in {minutes} minutes or contact an administrator.",
                "error",
            )
        elif status == AUTH_MFA_FAILED:
            flash("Invalid authentication code.", "error")
        else:
            flash("Invalid username or password.", "error")
    return render_template("auth/login.html", form=form)


@auth.route("/mfa", methods=["GET", "POST"])
@limiter.limit(_login_rate_limit)
def mfa():
    """Second authentication factor for users with TOTP enabled."""
    pending_id = session.get("mfa_user_id")
    if pending_id is None:
        return redirect(url_for("auth.login"))
    user = db.session.get(User, pending_id)
    if user is None or not user.mfa_enabled:
        session.pop("mfa_user_id", None)
        return redirect(url_for("auth.login"))

    form = MFAVerificationForm()
    if form.validate_on_submit():
        if user.verify_mfa_code(form.code.data):
            remember = bool(session.pop("mfa_remember", False))
            next_url = session.pop("mfa_next", None)
            session.pop("mfa_user_id", None)
            start_user_session(user, remember=remember)
            record_audit(Event.MFA_SUCCESS, actor=user, commit=False)
            db.session.commit()
            current_app.logger.info(f"User {user.email} passed two-factor authentication")
            flash("Two-factor authentication verified.", "success")
            if user.must_change_password:
                flash("You must change your password before continuing.", "warning")
                return redirect(url_for("auth.change_password"))
            if password_expired(user):
                flash("Your password has expired. Please choose a new one.", "warning")
                return redirect(url_for("auth.change_password"))
            if is_safe_url(next_url):
                return redirect(next_url)
            return redirect(url_for("main.index"))

        # Wrong code: audit it and count it towards the lockout policy.
        locked_now = user.record_failed_login()
        record_audit(
            Event.MFA_FAILED,
            actor=user,
            success=False,
            detail={"failed_attempts": user.failed_login_attempts},
        )
        if locked_now:
            session.pop("mfa_user_id", None)
            session.pop("mfa_remember", None)
            minutes = current_app.config["BLOGG_LOCKOUT_MINUTES"]
            flash(
                f"Too many failed attempts. Your account is locked for {minutes} minutes.",
                "error",
            )
            return redirect(url_for("auth.login"))
        flash("Invalid authentication code.", "error")
    return render_template("auth/mfa.html", form=form)


@auth.route("/confirm/<token>")
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for("main.index"))
    if current_user.confirm(token):
        db.session.commit()
        record_audit(
            Event.ACCOUNT_CONFIRMED,
            actor=current_user._get_current_object(),
            commit=False,
        )
        db.session.commit()
        flash("You have confirmed your account. Thanks!", "success")
    else:
        flash("The confirmation link is invalid or has expired.", "error")
    return redirect(url_for("main.index"))


@auth.before_app_request
def before_request():
    # Static assets (including blueprint static routes like bootstrap.static)
    # must never be redirected, otherwise styling and scripts break.
    if (
        request.endpoint == "static"
        or (request.endpoint and request.endpoint.endswith(".static"))
        or request.path.startswith("/static/")
    ):
        return

    user = current_user._get_current_object() if current_user.is_authenticated else None

    if user is None:
        # Flask-Login treats disabled accounts as unauthenticated
        # (UserMixin.is_authenticated follows is_active). If the session
        # still names a user, resolve them directly so a disabled account
        # gets the explicit "disabled" message instead of a silent logout.
        user_id = session.get("_user_id", "")
        user_pk, _ = User.parse_identity(user_id)
        candidate = db.session.get(User, user_pk) if user_pk is not None else None
        if candidate is not None and not candidate.active:
            end_user_session()
            flash("Your account has been disabled. Contact an administrator.", "error")
            if request.blueprint != "api":
                return redirect(url_for("auth.login"))
        elif candidate is not None:
            # load_user refused this identity: a sessions_revoked_at cutoff
            # was stamped after the session (or remember cookie) was issued.
            # End the browser session explicitly so it bounces to the login
            # page like any other revocation, instead of silently rendering
            # every public page as anonymous while the stale cookie lingers.
            end_user_session()
            flash("Your session has expired. Please log in again.", "warning")
            if request.blueprint != "api":
                return redirect(url_for("auth.login"))
        return

    # Disabled accounts lose their sessions immediately.
    if not user.active:
        end_user_session()
        flash("Your account has been disabled. Contact an administrator.", "error")
        return redirect(url_for("auth.login")) if request.blueprint != "api" else None

    # Server-side session validation (revocation + idle/absolute timeouts).
    if not validate_current_session(user):
        end_user_session()
        if request.blueprint == "api":
            return None
        flash("Your session has expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))

    # B1/B2: a forced password change (B1) or an expired password (B2, when
    # BLOGG_PASSWORD_MAX_AGE_DAYS > 0) gates every page except the form itself
    # (logout stays reachable as an escape hatch). The API enforces its own
    # 403 in api.authentication.before_request.
    if (
        request.blueprint != "api"
        and request.endpoint not in ("auth.change_password", "auth.logout")
        and (user.must_change_password or password_expired(user))
    ):
        flash(
            (
                "You must change your password before continuing."
                if user.must_change_password
                else "Your password has expired. Please choose a new one."
            ),
            "warning",
        )
        return redirect(url_for("auth.change_password"))

    user.ping()
    if not user.confirmed and request.blueprint != "auth":
        return redirect(url_for("auth.unconfirmed"))


@auth.route("/unconfirmed")
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for("main.index"))
    return render_template("auth/unconfirmed.html")


@auth.route("/logout", methods=["POST"])
@login_required
def logout():
    # POST-only: a GET logout would be forgeable (logout-CSRF) from any page.
    user = current_user._get_current_object()
    jti = end_user_session()
    record_audit(
        Event.LOGOUT,
        actor=user,
        target_type="session",
        target_label=jti,
        commit=True,
    )
    flash("You have been logged out.", "info")
    return redirect(url_for("main.index"))


@auth.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            email=form.email.data.strip().lower(),
            username=form.username.data,
            password=form.password.data,
        )
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, "Confirm Your Account", "auth/email/confirm", user=user, token=token)
        record_audit(Event.REGISTER, actor=user, commit=False)
        db.session.commit()

        flash(
            "Your account has been created. Check your inbox for a confirmation link, then log in.",
            "success",
        )
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@auth.route("/confirm", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def resend_confirmation():
    # POST-only: sending email on a GET made this forgeable cross-site.
    token = current_user.generate_confirmation_token()
    send_email(
        current_user.email,
        "Confirm Your Account",
        "auth/email/confirm",
        user=current_user,
        token=token,
    )
    flash("A new confirmation email has been sent to you by email.", "success")
    return redirect(url_for("main.index"))


@auth.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            if current_user.is_password_reused(form.password.data):
                flash("You cannot reuse a recent password.", "error")
                # Redirect (PRG) so refreshing cannot re-POST the form.
                return redirect(url_for("auth.change_password"))
            # Archive the outgoing hash first so it (and recent predecessors)
            # can never be reused, then set the new password.
            current_user.push_password_history()
            current_user.password = form.password.data
            # B1: a successful change always satisfies a forced change.
            current_user.must_change_password = False
            db.session.add(current_user._get_current_object())
            revoked = revoke_user_sessions(
                current_user._get_current_object(),
                keep_jti=session.get("session_jti"),
                detail={"reason": "password_change"},
            )
            # The cutoff stamped above invalidated this browser's identity
            # tag too; re-stamp it so the session performing the change
            # stays signed in while every other device (and any remembered
            # cookie) is refused by load_user().
            session["_user_id"] = current_user.get_id()
            record_audit(
                Event.PASSWORD_CHANGED,
                actor=current_user._get_current_object(),
                commit=False,
                detail={"method": "self_service", "sessions_revoked": revoked},
            )
            db.session.commit()
            flash(
                "Your password has been updated."
                + (f" Other sessions were signed out ({revoked})." if revoked else ""),
                "success",
            )
            return redirect(url_for("main.index"))
        else:
            flash("Invalid password.", "error")
    return render_template("auth/change_password.html", form=form)


@auth.route("/account/delete", methods=["POST"])
@login_required
def delete_account():
    """Self-service account deletion (B3): tombstone, never hard-delete."""
    user = current_user._get_current_object()
    if user.can(Permission.ADMIN) and active_administrator_count(exclude_user_id=user.id) == 0:
        flash("You cannot delete the last administrator account.", "error")
        return redirect(url_for("auth.security"))
    # Confirm with the current password (CSRF is enforced globally).
    password = request.form.get("password", "")
    if not password or not user.verify_password(password):
        flash("Invalid password.", "error")
        return redirect(url_for("auth.security"))
    # Tombstone first (posts and comments stay, the person does not), then
    # kill every credential that could still act as this user.
    user.anonymize()
    user.revoke_sessions()
    record_audit(
        Event.USER_DELETED,
        actor=user,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        detail={"method": "self_service"},
        commit=False,
    )
    db.session.commit()
    end_user_session()
    current_app.logger.info(f"Account deleted (self-service): user id {user.id}")
    flash(
        "Your account has been deleted. Your posts remain on the site anonymously.",
        "success",
    )
    return redirect(url_for("main.index"))


@auth.route("/reset", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for("main.index"))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user:
            token = user.generate_reset_token()
            send_email(
                user.email,
                "Reset Your Password",
                "auth/email/reset_password",
                user=user,
                token=token,
            )
            record_audit(
                Event.PASSWORD_RESET_REQUESTED,
                actor=user,
                commit=False,
            )
            db.session.commit()
        else:
            # Audit unknown-address attempts without revealing them to the caller.
            record_audit(
                Event.PASSWORD_RESET_REQUESTED,
                actor_label=form.email.data.lower(),
                success=False,
                detail={"reason": "unknown_email"},
            )
        flash(
            "An email with instructions to reset your password has been sent to you.",
            "success",
        )
        return redirect(url_for("auth.login"))
    return render_template("auth/reset_password.html", form=form)


@auth.route("/reset/<token>", methods=["GET", "POST"])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for("main.index"))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.reset_password(token, form.password.data)
        if user:
            db.session.commit()
            # Password reset invalidates every existing session for safety.
            revoke_user_sessions(user, detail={"reason": "password_reset"})
            record_audit(
                Event.PASSWORD_RESET_COMPLETED,
                actor=user,
                commit=False,
                detail={"method": "email_reset_link"},
            )
            db.session.commit()
            flash("Your password has been updated.", "success")
            return redirect(url_for("auth.login"))
        flash("The password reset link is invalid or has expired.", "error")
        return redirect(url_for("auth.login"))
    return render_template("auth/reset_password.html", form=form)


@auth.route("/change_email", methods=["GET", "POST"])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data.strip().lower()
            token = current_user.generate_email_change_token(new_email)
            send_email(
                new_email,
                "Confirm your email address",
                "auth/email/change_email",
                user=current_user,
                token=token,
            )
            flash(
                "An email with instructions to confirm your new email address has been sent to you.",
                "success",
            )
            return redirect(url_for("main.index"))
        else:
            # The form validates the email field itself; the only remaining
            # failure mode here is a wrong password.
            flash("Invalid password.", "error")
            return redirect(url_for("auth.change_email_request"))
    return render_template("auth/change_email.html", form=form)


@auth.route("/change_email/<token>")
@login_required
def change_email(token):
    if current_user.change_email(token):
        db.session.commit()
        record_audit(
            Event.EMAIL_CHANGED,
            actor=current_user._get_current_object(),
            commit=False,
        )
        db.session.commit()
        flash("Your email address has been updated.", "success")
    else:
        flash("Invalid request.", "error")
    return redirect(url_for("main.index"))


# ---------------------------------------------------------------------------
# Account security self-service: MFA enrollment + session/device management
# ---------------------------------------------------------------------------


@auth.route("/security")
@login_required
def security():
    sessions = (
        UserSession.query.filter_by(user_id=current_user.id, revoked_at=None)
        .order_by(UserSession.last_seen_at.desc())
        .all()
    )
    current_jti = session.get("session_jti")
    backup_codes = session.pop("mfa_backup_codes", None)
    return render_template(
        "auth/security.html",
        sessions=sessions,
        current_jti=current_jti,
        mfa_form=DisableMFAForm(),
        backup_codes=backup_codes,
    )


@auth.route("/security/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    if current_user.mfa_enabled:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("auth.security"))

    form = MFAVerificationForm()
    if not current_user.mfa_secret:
        current_user.generate_mfa_secret()
        db.session.add(current_user._get_current_object())
        db.session.commit()

    if form.validate_on_submit():
        if current_user.verify_mfa_code(form.code.data):
            current_user.mfa_enabled = True
            codes = current_user.generate_backup_codes()
            db.session.add(current_user._get_current_object())
            record_audit(
                Event.MFA_ENABLED,
                actor=current_user._get_current_object(),
                commit=False,
            )
            db.session.commit()
            session["mfa_backup_codes"] = codes
            flash("Two-factor authentication is now enabled.", "success")
            return redirect(url_for("auth.security"))
        record_audit(
            Event.MFA_FAILED,
            actor=current_user._get_current_object(),
            success=False,
            detail={"stage": "enrollment"},
        )
        flash("That code did not verify. Try again with a fresh code.", "error")
    return render_template(
        "auth/mfa_setup.html",
        form=form,
        secret=current_user.mfa_secret,
        qr_data_uri=mfa_qr_data_uri(current_user.mfa_provisioning_uri()),
    )


@auth.route("/security/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    form = DisableMFAForm()
    if not form.validate_on_submit():
        flash("Invalid request.", "error")
        return redirect(url_for("auth.security"))
    if not current_user.mfa_enabled:
        # Do not claim success (or demand a password) for a no-op.
        flash("Two-factor authentication is not enabled.", "info")
        return redirect(url_for("auth.security"))
    if not current_user.verify_password(form.password.data):
        flash("Invalid password.", "error")
        return redirect(url_for("auth.security"))
    current_user.disable_mfa()
    db.session.add(current_user._get_current_object())
    record_audit(
        Event.MFA_DISABLED,
        actor=current_user._get_current_object(),
        commit=False,
    )
    db.session.commit()
    flash("Two-factor authentication has been disabled.", "success")
    return redirect(url_for("auth.security"))


@auth.route("/security/sessions/<jti>/revoke", methods=["POST"])
@login_required
def session_revoke(jti):
    row = db.session.get(UserSession, jti)
    if row is None or row.user_id != current_user.id:
        flash("Session not found.", "error")
        return redirect(url_for("auth.security"))
    is_current = jti == session.get("session_jti")
    if row.revoked_at is None:
        row.revoked_at = utc_now()
    db.session.add(row)
    record_audit(Event.SESSION_REVOKED, target_type="session", target_label=jti, commit=False)
    db.session.commit()
    if is_current:
        session.pop("session_jti", None)
        end_user_session()
        flash("You have been signed out of this device.", "success")
        return redirect(url_for("auth.login"))
    flash("That session has been revoked.", "success")
    return redirect(url_for("auth.security"))


@auth.route("/security/sessions/revoke-others", methods=["POST"])
@login_required
def session_revoke_others():
    revoked = revoke_user_sessions(
        current_user._get_current_object(), keep_jti=session.get("session_jti")
    )
    # Same identity re-stamp as change_password: the cutoff kills every
    # pre-revocation identity, so refresh this device's tag to keep it in.
    session["_user_id"] = current_user.get_id()
    flash(
        f"Signed out of {revoked} other session(s)." if revoked else "No other sessions found.",
        "success" if revoked else "info",
    )
    return redirect(url_for("auth.security"))


@auth.route("/security/sessions/revoke-all", methods=["POST"])
@login_required
def session_revoke_all():
    """Sign out everywhere, including this device (full global logout)."""
    user = current_user._get_current_object()
    revoked = revoke_user_sessions(user, keep_jti=None, detail={"scope": "all"})
    jti = end_user_session()  # wipes cookie state for the current browser too
    record_audit(
        Event.LOGOUT,
        actor=user,
        target_type="session",
        target_label=jti,
        detail={"scope": "all", "revoked": revoked},
        commit=True,
    )
    flash("Signed out of all devices." if revoked else "Signed out everywhere.", "success")
    return redirect(url_for("auth.login"))

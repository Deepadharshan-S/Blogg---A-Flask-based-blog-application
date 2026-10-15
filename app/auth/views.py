from urllib.parse import urlsplit

from flask import current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .. import db, limiter
from ..email import send_email
from ..models import User
from . import auth
from .forms import (
    ChangeEmailForm,
    ChangePasswordForm,
    LoginForm,
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


@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            current_app.logger.info(f"User logged in: {user.email}")  # Log successful login
            next_url = request.args.get("next")
            if not is_safe_url(next_url):
                next_url = url_for("main.index")
            return redirect(next_url)
        current_app.logger.warning(f"Failed login attempt: {form.email.data}")
        flash("Invalid username or password.")
    return render_template("auth/login.html", form=form)


@auth.route("/confirm/<token>")
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for("main.index"))
    if current_user.confirm(token):
        db.session.commit()
        flash("You have confirmed your account. Thanks!")
    else:
        flash("The confirmation link is invalid or has expired.")
    return redirect(url_for("main.index"))


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if (
            not current_user.confirmed
            and request.blueprint != "auth"
            and request.endpoint != "static"
        ):
            return redirect(url_for("auth.unconfirmed"))


@auth.route("/unconfirmed")
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for("main.index"))
    return render_template("auth/unconfirmed.html")


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
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

        flash("You can now login.")
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@auth.route("/confirm")
@login_required
@limiter.limit("5 per hour")
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(
        current_user.email,
        "Confirm Your Account",
        "auth/email/confirm",
        user=current_user,
        token=token,
    )
    flash("A new confirmation email has been sent to you by email.")
    return redirect(url_for("main.index"))


@auth.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash("Your password has been updated.")
            return redirect(url_for("main.index"))
        else:
            flash("Invalid password.")
    return render_template("auth/change_password.html", form=form)


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
        flash("An email with instructions to reset your password has been sent to you.")
        return redirect(url_for("auth.login"))
    return render_template("auth/reset_password.html", form=form)


@auth.route("/reset/<token>", methods=["GET", "POST"])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for("main.index"))
    form = PasswordResetForm()
    if form.validate_on_submit():
        if User.reset_password(token, form.password.data):
            db.session.commit()
            flash("Your password has been updated.")
            return redirect(url_for("auth.login"))
        else:
            flash("The password reset link is invalid or has expired.")
            return redirect(url_for("main.index"))
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
                "An email with instructions to confirm your new email address has been sent to you."
            )
            return redirect(url_for("main.index"))
        else:
            flash("Invalid email or password.")
    return render_template("auth/change_email.html", form=form)


@auth.route("/change_email/<token>")
@login_required
def change_email(token):
    if current_user.change_email(token):
        db.session.commit()
        flash("Your email address has been updated.")
    else:
        flash("Invalid request.")
    return redirect(url_for("main.index"))

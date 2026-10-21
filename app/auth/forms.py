import re

from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp

from ..models import User


def validate_strong_password(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        raise ValidationError("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError("Password must contain at least one special character.")


class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Length(1, 64), Email()],
        filters=[lambda x: x.strip().lower() if isinstance(x, str) else x],
    )
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log In")


class RegistrationForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Length(1, 64), Email()],
        filters=[lambda x: x.strip().lower() if isinstance(x, str) else x],
    )
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(1, 64),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Usernames must have only letters, numbers, dots or underscores",
            ),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            EqualTo("password2", message="Passwords must match."),
            validate_strong_password,
        ],
    )
    password2 = PasswordField("Confirm password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        normalized = field.data.strip().lower() if field.data else ""
        if User.query.filter_by(email=normalized).first():
            raise ValidationError("Email already registered.")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Username already in use.")


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField("Old password", validators=[DataRequired()])
    password = PasswordField(
        "New password",
        validators=[
            DataRequired(),
            EqualTo("password2", message="Passwords must match."),
            validate_strong_password,
        ],
    )
    password2 = PasswordField("Confirm new password", validators=[DataRequired()])
    submit = SubmitField("Update Password")


class PasswordResetRequestForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Length(1, 64), Email()],
        filters=[lambda x: x.strip().lower() if isinstance(x, str) else x],
    )
    submit = SubmitField("Reset Password")


class PasswordResetForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            EqualTo("password2", message="Passwords must match"),
            validate_strong_password,
        ],
    )
    password2 = PasswordField("Confirm password", validators=[DataRequired()])
    submit = SubmitField("Reset Password")


class ChangeEmailForm(FlaskForm):
    email = StringField(
        "New Email",
        validators=[DataRequired(), Length(1, 64), Email()],
        filters=[lambda x: x.strip().lower() if isinstance(x, str) else x],
    )
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Update Email Address")

    def validate_email(self, field):
        normalized = field.data.strip().lower() if field.data else ""
        if User.query.filter_by(email=normalized).first():
            raise ValidationError("Email already registered.")


class MFAVerificationForm(FlaskForm):
    # Accepts a 6-digit TOTP code or an 8-character backup code (xxxx-xxxx).
    code = StringField(
        "Authentication code",
        validators=[DataRequired(), Length(6, 32)],
    )
    submit = SubmitField("Verify")


class DisableMFAForm(FlaskForm):
    password = PasswordField("Confirm with your password", validators=[DataRequired()])
    submit = SubmitField("Disable two-factor authentication")

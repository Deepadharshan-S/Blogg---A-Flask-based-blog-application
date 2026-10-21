from flask_wtf import FlaskForm
from wtforms import BooleanField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length

from ..models import Permission


class RoleForm(FlaskForm):
    name = StringField("Role name", validators=[DataRequired(), Length(1, 64)])
    follow = BooleanField("FOLLOW — follow other users")
    comment = BooleanField("COMMENT — comment on posts")
    write = BooleanField("WRITE — publish posts")
    moderate = BooleanField("MODERATE — hide offensive comments")
    admin = BooleanField("ADMIN — full administrative access")
    manage_users = BooleanField("MANAGE_USERS — manage accounts in the admin console")
    view_audit = BooleanField("VIEW_AUDIT — read the security audit log")
    submit = SubmitField("Save Role")

    def permission_names(self):
        """Permission names of the checkboxes that are ticked."""
        return [name for name in Permission.all() if getattr(self, name.lower()).data]

    def load_permissions(self, permissions):
        """Tick the checkboxes contained in an existing permission bitmask."""
        for name, value in Permission.all().items():
            getattr(self, name.lower()).data = bool(permissions) and bool(
                permissions & value == value
            )


class UserFilterForm(FlaskForm):
    """GET-only filter form for the user list."""

    class Meta:
        csrf = False

    q = StringField("Search")
    role = SelectField("Role", choices=[("", "All roles")])
    status = SelectField(
        "Status",
        choices=[
            ("", "All"),
            ("active", "Active"),
            ("disabled", "Disabled"),
            ("locked", "Locked"),
            ("unconfirmed", "Unconfirmed"),
        ],
    )

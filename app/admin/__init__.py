from flask import Blueprint

admin = Blueprint("admin", __name__, url_prefix="/admin")

from ..models import Permission, Role  # noqa: E402
from . import views  # noqa: E402, F401


@admin.app_context_processor
def inject_admin_helpers():
    """Expose Role/Permission helpers to admin templates."""
    return dict(Permission=Permission, Role=Role)

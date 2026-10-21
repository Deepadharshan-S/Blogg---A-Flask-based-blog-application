from functools import wraps

from flask import abort
from flask_login import current_user

from .models import Permission


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def admin_required(f):
    return permission_required(Permission.ADMIN)(f)


def manage_users_required(f):
    """Admin console: user lifecycle management (role, disable, unlock...)."""
    return permission_required(Permission.MANAGE_USERS)(f)


def audit_required(f):
    """Admin console: audit-log access."""
    return permission_required(Permission.VIEW_AUDIT)(f)


def owner_or_permission(user, obj, owner_attr="author", permission=Permission.ADMIN):
    """Object-level authorization shared by the web views and the REST API.

    The owner of a resource always passes; everyone else needs ``permission``.
    Returns a bool so callers can decide between 403 responses and flashes.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    owner = getattr(obj, owner_attr, None) if obj is not None else None
    if owner is not None and user == owner:
        return True
    return user.can(permission)

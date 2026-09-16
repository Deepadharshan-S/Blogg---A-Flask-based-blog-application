import base64
from functools import wraps

from flask import g, jsonify, request

from ..models import AnonymousUser, User
from . import api
from .errors import forbidden, unauthorized


def get_auth_user_from_request():
    auth_header = request.headers.get("Authorization", "")

    # 1. Bearer Token Auth
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        user = User.verify_auth_token(token)
        if user:
            return user

    # 2. Basic Auth (email:password)
    elif auth_header.startswith("Basic "):
        try:
            encoded_creds = auth_header[6:].strip()
            decoded = base64.b64decode(encoded_creds).decode("utf-8")
            email, password = decoded.split(":", 1)
            user = User.query.filter_by(email=email).first()
            if user and user.verify_password(password):
                return user
        except Exception:
            pass

    return None


@api.before_request
def before_request():
    user = get_auth_user_from_request()
    g.current_user = user if user is not None else AnonymousUser()


def token_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.current_user.is_authenticated:
            return unauthorized(
                "Authentication required. Include a valid Bearer token in the Authorization header."
            )
        return f(*args, **kwargs)

    return decorated


def permission_required_api(permission):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not g.current_user.can(permission):
                return forbidden("Insufficient permissions to perform this action.")
            return f(*args, **kwargs)

        return decorated

    return decorator


@api.route("/tokens", methods=["POST"])
def get_token():
    # Support credentials from Basic Auth header or JSON request body
    user = None
    if g.current_user.is_authenticated:
        user = g.current_user
    elif request.is_json:
        data = request.get_json() or {}
        email = data.get("email")
        password = data.get("password")
        if email and password:
            candidate = User.query.filter_by(email=email).first()
            if candidate and candidate.verify_password(password):
                user = candidate

    if user is None or not user.is_authenticated:
        return unauthorized("Invalid email or password.")

    if not user.confirmed:
        return forbidden("Account is not confirmed.")

    token = user.generate_auth_token(expiration=3600)
    return jsonify({"token": token, "expiration": 3600, "user": user.to_json()})

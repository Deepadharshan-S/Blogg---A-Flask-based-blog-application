from flask import jsonify

from . import api


def bad_request(message):
    response = jsonify({"error": "bad request", "message": message})
    response.status_code = 400
    return response


def unauthorized(message="Authentication required"):
    response = jsonify({"error": "unauthorized", "message": message})
    response.status_code = 401
    return response


def forbidden(message="Permission denied"):
    response = jsonify({"error": "forbidden", "message": message})
    response.status_code = 403
    return response


def not_found(message="Resource not found"):
    response = jsonify({"error": "not found", "message": message})
    response.status_code = 404
    return response


@api.errorhandler(400)
def handle_400(e):
    return bad_request(str(e))


@api.errorhandler(401)
def handle_401(e):
    return unauthorized(str(e))


@api.errorhandler(403)
def handle_403(e):
    return forbidden(str(e))


@api.errorhandler(404)
def handle_404(e):
    return not_found(str(e))


@api.errorhandler(500)
def handle_500(e):
    response = jsonify(
        {"error": "internal server error", "message": "An unexpected error occurred"}
    )
    response.status_code = 500
    return response

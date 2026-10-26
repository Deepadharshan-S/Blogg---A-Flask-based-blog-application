from flask import current_app, jsonify, render_template, request

from . import main


def _wants_json():
    """API paths (and JSON-only clients) get a JSON body, browsers a page."""
    return request.path.startswith("/api/") or (
        request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    )


def _error_response(code, title, description, json_error):
    """Render the shared themed error page (or JSON) for the given status."""
    if _wants_json():
        return jsonify({"error": json_error, "message": description}), code
    return (
        render_template("error.html", code=code, title=title, description=description),
        code,
    )


@main.app_errorhandler(400)
def bad_request(e):
    current_app.logger.error(f"400 error: {str(e)}")
    description = getattr(e, "description", None) or "The request could not be understood."
    return _error_response(400, "Bad Request", description, "bad request")


@main.app_errorhandler(403)
def forbidden(e):
    current_app.logger.error(f"403 error: {str(e)}")
    return _error_response(403, "Access Forbidden", "Permission denied.", "forbidden")


@main.app_errorhandler(404)
def page_not_found(e):
    current_app.logger.error(f"404 error: {str(e)}")
    return _error_response(
        404,
        "Page Not Found",
        "Oops! The page you are looking for does not exist. It might have been moved or deleted.",
        "not found",
    )


@main.app_errorhandler(405)
def method_not_allowed(e):
    current_app.logger.error(f"405 error: {str(e)}")
    description = getattr(e, "description", None) or "The method is not allowed for this URL."
    return _error_response(405, "Method Not Allowed", description, "method not allowed")


@main.app_errorhandler(429)
def rate_limited(e):
    current_app.logger.error(f"429 error: {str(e)}")
    description = getattr(e, "description", None) or (
        "You have made too many requests. Please wait a moment and try again."
    )
    return _error_response(429, "Too Many Requests", description, "too many requests")


@main.app_errorhandler(500)
def internal_server_error(e):
    current_app.logger.error(f"500 error: {str(e)}")
    return _error_response(
        500,
        "Internal Server Error",
        "Oops! Something went wrong on our end. We're working to fix it. Please try again later.",
        "internal server error",
    )

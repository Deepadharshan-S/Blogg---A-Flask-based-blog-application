from flask import current_app, jsonify, render_template, request

from . import main


@main.app_errorhandler(404)
def page_not_found(e):
    current_app.logger.error(f"404 error: {str(e)}")
    if request.path.startswith("/api/") or (
        request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    ):
        return jsonify(
            {"error": "not found", "message": "The requested URL was not found on the server."}
        ), 404
    return render_template("404.html"), 404


@main.app_errorhandler(500)
def internal_server_error(e):
    current_app.logger.error(f"500 error: {str(e)}")
    if request.path.startswith("/api/") or (
        request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    ):
        return jsonify(
            {"error": "internal server error", "message": "An unexpected error occurred."}
        ), 500
    return render_template("500.html"), 500


@main.app_errorhandler(403)
def forbidden(e):
    current_app.logger.error(f"403 error: {str(e)}")
    if request.path.startswith("/api/") or (
        request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    ):
        return jsonify({"error": "forbidden", "message": "Permission denied."}), 403
    return render_template("403.html"), 403

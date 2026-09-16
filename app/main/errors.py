from flask import render_template, current_app
from . import main

@main.app_errorhandler(404)
def page_not_found(e):
    current_app.logger.error(f'404 error: {str(e)}')
    return render_template('404.html'), 404

@main.app_errorhandler(500)
def internal_server_error(e):
    current_app.logger.error(f'500 error: {str(e)}')
    return render_template('500.html'), 500

@main.app_errorhandler(403)
def forbidden(e):
    current_app.logger.error(f'403 error: {str(e)}')
    return render_template('403.html'), 403

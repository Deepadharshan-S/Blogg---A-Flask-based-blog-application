import os
from concurrent.futures import ThreadPoolExecutor

from flask import current_app, render_template
from flask_mail import Message

from . import mail

_email_executor = None


def get_email_executor(max_workers=None):
    global _email_executor
    if _email_executor is None:
        if max_workers is None:
            try:
                max_workers = int(os.environ.get("BLOGG_EMAIL_MAX_WORKERS", "4"))
            except (ValueError, TypeError):
                max_workers = 4
        _email_executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="email-worker"
        )
    return _email_executor


def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Failed to send email: {e}", exc_info=True)


def send_email(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    prefix = app.config.get("BLOGG_MAIL_SUBJECT_PREFIX", "[BLOGG]").strip()
    msg = Message(
        subject=f"{prefix} {subject}",
        sender=app.config["BLOGG_MAIL_SENDER"],
        recipients=[to],
    )
    msg.body = render_template(template + ".txt", **kwargs)
    msg.html = render_template(template + ".html", **kwargs)

    executor = get_email_executor()
    try:
        return executor.submit(send_async_email, app, msg)
    except Exception as e:
        app.logger.error(f"Failed to submit email task to executor: {e}", exc_info=True)
        return None

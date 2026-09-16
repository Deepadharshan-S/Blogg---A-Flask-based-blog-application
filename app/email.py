from threading import Thread

from flask import current_app, render_template
from flask_mail import Message

from . import mail


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(to, subject, template, **kwargs):
    prefix = current_app.config.get("BLOGG_MAIL_SUBJECT_PREFIX", "[BLOGG]").strip()
    msg = Message(
        subject=f"{prefix} {subject}",
        sender=current_app.config["BLOGG_MAIL_SENDER"],
        recipients=[to],
    )
    msg.body = render_template(template + ".txt", **kwargs)
    msg.html = render_template(template + ".html", **kwargs)

    # Start a new thread to send the email
    thread = Thread(target=send_async_email, args=(current_app._get_current_object(), msg))
    thread.start()
    return thread

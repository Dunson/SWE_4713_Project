from flask import render_template, request
from flask_mail import Message

from . import mail, views


def send_recovery(user):
    token = user.get_reset_token()

    msg = Message()
    msg.subject = "Reset Password"
    msg.sender = user.email
    msg.recipients = [user.email]
    msg.html = render_template('reset_email.html', user = user, token = token)

    mail.send(msg)
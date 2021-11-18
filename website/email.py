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


def send_email(user):
    a = []
    f = request.form
    for key in f.keys():
        for value in f.getlist(key):
            a = list.append(value)

    msg = a[2]
    msg.subject = a[0]
    msg.sender = user.email
    msg.recipients = a[1]
    msg.html = render_template('email_user.html', user=user)

    mail.send(msg)

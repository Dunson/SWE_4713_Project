from flask import render_template
from flask_mail import Message
from . import mail


def send_recovery(user):
    token = user.get_reset_token()

    msg = Message()
    msg.subject = "Reset Password"
    msg.sender = user.email
    msg.recipients = [user.email]
    msg.html = render_template('reset_email.html', user = user, token = token)

    mail.send(msg)

def send_email_to_user(user):
    msg = Message()
    msg.subject = "__"  # get input from user
    msg.sender = user.email
    msg.recipients = [user.email]
    msg.html = render_template('')  # tie to the admin user on choa page?
  


    
    

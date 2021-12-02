from sqlalchemy.orm import backref

from werkzeug.datastructures import _CacheControl
from werkzeug.security import generate_password_hash, check_password_hash

from . import db 
from flask_login import UserMixin
from sqlalchemy.sql import func
from time import time
import os
import jwt
import re
from datetime import datetime, timedelta
import smtplib


# Defined User table for database
class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)  # unique identifier
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    oldPassword = db.Column(db.String(150))
    firstName = db.Column(db.String(150))
    lastName = db.Column(db.String(150))
    userName = db.Column(db.String(150))
    hasAdmin = db.Column(db.Boolean, default=False)
    hasMan = db.Column(db.Boolean, default=False)
    status = db.Column(db.Boolean, default=False)
    creationDate = db.Column(db.Date())
    expirationDate = db.Column(db.Date())
    suspensionDate = db.Column(db.Date())
    suspensionEnd = db.Column(db.Date())
    accounts = db.relationship("Account", backref="user_backref", lazy=True)

    def reset_password(self, password, commit=False):
        self.oldPassword = self.password
        self.password = generate_password_hash(password, method='sha256')

        if commit:
            db.session.commit()

    def get_reset_token(self, expires=500):
        return jwt.encode({'reset_password': self.email, 'exp': time() + expires},
                           key=os.getenv('HOME'),algorithm="HS256")

    @staticmethod
    def verify_reset_token(token):
        try:
            email = jwt.decode(token, key=os.getenv('HOME'),algorithms="HS256")['reset_password']
            print(email)
        except Exception as e:
            print(e)
            return
        return User.query.filter_by(email=email).first()

    # Method for password validation
    def password_check(self, password, passwd2): 

        length_error = len(password) < 8
        digit_error = re.search(r"\d", password) is None
        uppercase_error = re.search(r"[A-Z]", password) is None
        lowercase_error = re.search(r"[a-z]", password) is None
        symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None
        password_ok = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)
        return password_ok

    def update_user(self, usrName, usrEmail, usrFirst, usrLast, usrMan, usrAdmin, usrStat, commit=False):
        self.firstName = usrFirst
        self.lastName = usrLast 
        self.email = usrEmail
        self.hasMan = usrMan
        self.hasAdmin = usrAdmin
        self.status = usrStat
        self.userName = usrName

        if commit:
            db.session.commit()
            return True

    def password_expire(self):
        password_exp = self.creationDate + timedelta(days=365)
        return password_exp

    def notify_password_exp(self):

        '''Report:
        Get Username, email and expDate if datetime.now >= password_expire() '''
        if self.hasAdmin and datetime.now() == self.password_expire() - timedelta(days=3):
            return True

class CannotBeDeactivatedError(Exception):
    # Raised when the user cannot be deactivated because they have a ledger balance above 0
    pass


class Error(db.Model):
    __tablename__ = 'errorLog'
    error_id = db.Column(db.Integer, primary_key=True)
    error_desc = db.Column(db.String(200))

    def __init__(self, error_desc):
        self.error_desc = error_desc

    def errorcreate(self, error_desc, commit=False):

        self.error_desc = error_desc

        if commit:
            db.session.commit()


class Account(db.Model):
    
    acc_num = db.Column(db.Integer, primary_key=True)  # unique identifier. Needs adjusting
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

    acc_name = db.Column(db.String(150), unique=True)
    acc_desc = db.Column(db.String(150))
    acc_cat = db.Column(db.String(150))
    # acc_sub_cat = db.Column(db.String(150)
   
    init_bal = db.Column(db.Float)
    # acc_bal = db.Column(db.Float)
    # acc_deb = db.Column(db.Float)
    # acc_cred = db.Column(db.Float)

    acc_statement = db.Column(db.String(150))
    # acc_order = db.Column(db.Integer)

    # creation_date = db.Column(db.Date())
    # creation_time = db.Column(db.Time(), nullable = False)

    # acc_status = db.Column(db.Boolean, default = False)
    # acc_comment = db.Column(db.String(150))
    db.relationship('Journal', backref='user_journals')

    def user_balance_above_zero(self):
        if self.init_bal > 0:
            return True
        else:
            return False

    # function to determine if an account can be deactivated, raises an error if user_balance_above_zero == True
    def cannot_deactivate(self):
        try:
            self.user_balance_above_zero()
        except CannotBeDeactivatedError:
            return "User cannot be deactivated, account balance over 0."
            # I would suggest returning an error message here instead of this return statement.

    # function to format balances to comma and 2 decimal place. Must pass in a number
    def format_acc_balance(self, n):
        num = "{:,.2f}".format(n)
        return num


# A journal holds ledger entries
class Journal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.now)
    ledger_entries = db.relationship('Ledger', backref='entries')
    assoc_acc = db.Column(db.Integer, db.ForeignKey('account.acc_num'))


class Ledger(db.Model):

    entry_num = db.Column(db.Integer, primary_key=True)
    entry_desc = db.Column(db.String(150))
    entry_date = db.Column(db.Date())
    entry_bal = db.Column(db.Float)
    entry_cred = db.Column(db.Float)
    entry_deb = db.Column(db.Float)
    isApproved = db.Column(db.String(25), nullable=False, default="Pending")
    journal_id = db.Column(db.Integer, db.ForeignKey('journal.id'))
    acc_num = db.Column(db.Integer, db.ForeignKey('account.acc_num'))
    attaches = db.relationship('Attachments', backref='atts')


    # function to format balances to comma and 2 decimal place. Must pass in a number
    def format_led_balance(self, n):
        num = "{:,.2f}".format(n)
        return num

    # Tells the page not to display unapproved entries into the ledger
    def do_not_display(self):
        if self.isApproved == 'Pending' or self.isApproved == 'Not Approved':
            return True
        else:
            return False


# add attachments to the ledger
class Attachments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attachment = db.Column(db.BLOB, nullable=False)
    ledger_id = db.Column(db.Integer, db.ForeignKey('ledger.entry_num'))

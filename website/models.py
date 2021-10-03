from werkzeug.security import generate_password_hash
from . import db 
from flask_login import UserMixin
from sqlalchemy.sql import func
from time import time
import os
import jwt
import re
from datetime import datetime



#Defined User Model for database
class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True) #unique identifier
    email = db.Column(db.String(150), unique = True)
    password = db.Column(db.String(150))
    oldPassword = db.Column(db.String(150))
    firstName = db.Column(db.String(150))
    lastName = db.Column(db.String(150))
    userName = db.Column(db.String(150))
    hasAdmin = db.Column(db.Boolean, default = False)
    hasMan = db.Column(db.Boolean, default = False)
    status = db.Column(db.Boolean, default = False)
    creationDate = db.Column(db.Date())
    
    



    def reset_password(self, password, commit=False):
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


    #Method for password validation
    #This method was supplied by: 
    def password_check(password):
        
        length_error = len(password) < 8

        digit_error = re.search(r"\d", password) is None

        uppercase_error = re.search(r"[A-Z]", password) is None

        lowercase_error = re.search(r"[a-z]", password) is None

        symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

        password_ok = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)

        return password_ok



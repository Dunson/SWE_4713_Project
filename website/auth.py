from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from .email import send_recovery
from datetime import datetime

auth = Blueprint('auth', __name__)

#Back-end for logging in
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Login Succeful!', category='success')
                login_user(user)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect Password!', category='error')
        else:
            flash('Required fields are empty!', category='error')
    return render_template("login.html", user = current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))



@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        lastName = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        #Generates userName based on firstname, lastname and month&year of when account was created
        def userNameGen(first, last):
            first = firstName
            last = lastName
            currMonth = str(datetime.now().month)
            currYear = str(datetime.now().year)

            if len(currMonth) < 2:
                currMonth = '0' + currMonth
            userName = first[0] + last + currMonth + currYear[2] + currYear[3]
            print(userName)
            return userName



        user = User.query.filter_by(email=email).first()
        pwd_check = User.password_check(password1)


        # The password conditions still need to satisfy the requirements
        if user:
            flash('An account with that email already exists!', category='error')
        elif len(firstName) < 2:
            flash('First name must be greater than 1 character', category='error')
        elif password1 != password2: # This compares the two passwords
            flash('Passwords do not match', category='error')
        elif not pwd_check:  
            flash('Password does not meet the requirements', category='error')
        else:
            # Add user to database
            new_user = User(email=email, firstName=firstName, lastName=lastName, 
                password=generate_password_hash(password1, method='sha256'), 
                userName = userNameGen(firstName, lastName),
                hasAdmin = False, hasMan = False)
            
            db.session.add(new_user)
            db.session.commit()     
            
            flash('Account Created', category='success')
            return redirect(url_for('auth.login'))

    
    return render_template("signUp.html", user = current_user)


@auth.route('/recovery', methods = ['GET', 'POST'])
def recovery_Page():
    if request.method == 'POST':
        email = request.form.get('email')
        
        #Check if email is in database
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('That email was not found in our records.', category='error')
        else:
            send_recovery(user)
            flash('Recovery email sent!', category='success')
            return redirect(url_for('auth.login'))

    return render_template('passwordRecov.html', user= current_user)



@auth.route('/reset_verified/<token>', methods = ['GET', 'POST'])
def reset_password(token):

    user = User.verify_reset_token(token)

    if not user:
        print('no user found')
        flash('Reset Token Expired!',category='error')
        return redirect(url_for('auth.login'))

    password1 = request.form.get('password1')
    password2 = request.form.get('password2')
    
    if password1:
        if password1 == password2:
            user.reset_password(password1, commit=True)
            flash('Password Reset Successful!!', category='success')
            return redirect(url_for('auth.login'))
        else:
            flash('Passwords must match!', category='error')

    return render_template('reset_verified.html', user=current_user)   


#Method for admin portal access. 
#This works under the assumption that there is only one admin in the database
@auth.route('/adminPortal', methods = ['GET', 'POST'])
@login_required
def adminPort():
    
    #Query the database for an admin user
    adminUser = User.query.filter_by(hasAdmin = True).first()

    #check if that admin user is the current user
    if adminUser == current_user:
        return render_template('adminPortal.html', user = current_user, query = User.query.all())
    else:
        flash('You do not have access to this page!', category='error')
        return redirect(url_for('views.home'))


    #return render_template('adminPortal.html', user = current_user)


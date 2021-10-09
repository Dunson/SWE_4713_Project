from os import error
from flask import Blueprint, render_template, request, flash, redirect, url_for
from sqlalchemy.orm import query
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from .email import send_recovery
from datetime import datetime

auth = Blueprint('auth', __name__)

searchID = 'none'


#Back-end for logging in
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:

            if user.status == False:
                flash('Your account must be activated by an administrator.', category='error')
                return redirect(url_for('auth.login'))
            
            if user.hasAdmin == True:
                flash('Admin login successful!', category='success')
                login_user(user)
                return redirect(url_for('auth.adminPort'))

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
                hasAdmin = False, hasMan = False, status = False, 
                creationDate = datetime.now())
            
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
        flash('Reset Token Expired!',category='error')
        return redirect(url_for('auth.login'))

    password1 = request.form.get('password1')
    password2 = request.form.get('password2')

    if password1:
        if password1 == password2:
            print(check_password_hash(user.oldPassword, password1))

            if check_password_hash(user.oldPassword, password1):
                flash('You can not reuse an old password!', category='error')
                return redirect(url_for('auth.reset_password', token = token))

            user.reset_password(password1, commit=True)
            flash('Password Reset Successful!!', category='success')
            return redirect(url_for('auth.login'))
        else:
            flash('Passwords must match!', category='error')

    return render_template('reset_verified.html', user=current_user)   




#Method for admin dashboard
@auth.route('/adminPortal', methods = ['GET', 'POST'])
@login_required
def adminPort():

    #qID = 0
    #Logic for updating accounts
    if request.method == 'POST':
        global searchID
        searchID = request.form.get('searchBar')
        if len(searchID) < 1:
            flash('Search field can not be blank.', category='error')
            return redirect(url_for('auth.adminPort'))
        else:
            return redirect(url_for('auth.accountEdit'))

    
    else:

        if current_user.hasAdmin:
            return render_template('adminPortal.html', 
                user = current_user, query = User.query.all())
        else:
            flash('You do not have access to this page.', category='error')
            return redirect(url_for('views.home'))


@auth.route('/editAccount', methods = ['GET', 'POST'])
@login_required
def accountEdit():

    usr_status = False
    usr_hasMan = False
    usr_hasAdmin = False

    qID = int(searchID)
    user_to_update = User.query.filter_by(id = qID).first()

    if request.method == 'POST':

        email = request.form.get("email")
        firstName = request.form.get("firstName")
        lastName = request.form.get("lastName")
        status = request.form.get("activeButton")
        hasMan = request.form.get("manButton")
        hasAdmin = request.form.get("adminButton")

        if status == 'on':
            usr_status = True
        if hasMan == 'on':
            usr_hasMan = True
        if hasAdmin == 'on':
            usr_hasAdmin = True

        userName = userNameGenGlobal(firstName, lastName)
        if len(firstName) < 2 or len(lastName) < 2 or len(email) < 1:
            flash('Input fields can not be blank.', category='error')
        else:
            
            updateStat = user_to_update.update_user(userName, email, firstName, lastName, usr_hasMan, usr_hasAdmin, usr_status, commit=True)
            if updateStat:
                flash('Account updated successfully', category='success')
                return redirect(url_for('auth.adminPort'))
            else:
                flash('Account Update Failed!', category='error')
        
    
    return render_template('editAccount.html', user=current_user, query = User.query.all(), searchID = searchID)


def userNameGenGlobal(first, last):
            first = first
            last = last
            currMonth = str(datetime.now().month)
            currYear = str(datetime.now().year)

            if len(currMonth) < 2:
                currMonth = '0' + currMonth
            
            userName = first[0] + last + currMonth + currYear[2] + currYear[3]
            return userName
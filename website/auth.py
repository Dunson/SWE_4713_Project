from os import error
from smtplib import SMTPAuthenticationError

from flask import Blueprint, render_template, request, flash, redirect, url_for
from sqlalchemy.orm import query
from .models import User, Account, Ledger
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, mail
from flask_login import login_user, login_required, logout_user, current_user
from .email import send_recovery
from datetime import datetime, timedelta
from flask_mail import Mail, Message
auth = Blueprint('auth', __name__)

#GLOBAL Variables
SEARCHID = 'none'
ACC_ID = 'none'
LEDGER_NUM = 0
ATTEMPT_COUNT = 0

# GLOBAL ERROR MESSAGES
email_error = 'The email provided is either not correct or there is an internal error with the server'
no_access = 'You do not have access to this page.'
ipw = 'Incorrect Password!'
fields_empty = 'Required fields are empty!'
not_activated = 'Your account must be activated by an administrator.'
acc_exists = 'An account with that email already exists!'
gt_1_c = 'First name must be greater than 1 character'
mismatch_pw = 'Passwords do not match'
cannot_reuse = 'You can not reuse an old password!'
does_not_meet_reqs = 'Password does not meet the requirements'
email_not_found = 'That email was not found in our records.'
reset_token_expired = 'Reset Token Expired!'
no_blank = 'Input field can not be blank.'


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:

            if user.status == False:
                flash(not_activated, category='error')
                return redirect(url_for('auth.login'))

            if user.hasAdmin == True and check_password_hash(user.password, password):
                flash('Admin login successful!', category='success')
                login_user(user)
                return redirect(url_for('auth.adminPort'))


            if check_password_hash(user.password, password):
                flash('Login Succeful!', category='success')
                login_user(user)

                return redirect(url_for('views.home'))
            else:
                flash(ipw, category='error')

            # Limits login attempts 
            if check_password_hash(user.password, password):
                flash('Login Succeful!', category='success')
                login_user(user)
                global ATTEMPT_COUNT
                ATTEMPT_COUNT = 0
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect Password! Attempt: ' + str(ATTEMPT_COUNT), category='error')
                ATTEMPT_COUNT += 1
            
            if ATTEMPT_COUNT > 3:    
                flash('You have exceeded maximum login attempts. Your account has been deactivated.', category='error')
                User.deactivate_user(user, commit = True)
                return render_template('login.html', user=current_user)

        else:
            flash(fields_empty, category='error')
    return render_template("login.html", user=current_user)


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
        password_one = request.form.get('password1')
        password_two = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        pwd_check = User.password_check(password_one)

        # Creation validation logic
        if user:
            flash(acc_exists, category='error')
        elif len(firstName) < 2:
            flash(gt_1_c, category='error')
        elif password_one != password_two:  # This compares the two passwords
            flash(mismatch_pw, category='error')
        elif not pwd_check:
            flash(does_not_meet_reqs, category='error')
        else:
            # Add user to database
            new_user = User(email=email, firstName=firstName, lastName=lastName,
                            password=generate_password_hash(
                                password_one, method='sha256'),
                            userName=userNameGenGlobal(firstName, lastName),
                            hasAdmin=False, hasMan=False, status=False,
                            creationDate=datetime.now(), expirationDate=datetime.now() + timedelta(days=365))

            db.session.add(new_user)
            db.session.commit()

            flash('Account Created! Note: The admininstrator must activate your account before you can login.', category='success')
            return redirect(url_for('auth.login'))

    return render_template("signUp.html", user=current_user)


@auth.route('/recovery', methods=['GET', 'POST'])
def recovery_Page():
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if email is in database
        user = User.query.filter_by(email=email).first()
        if not user:
            flash(email_not_found, category='error')
        else:
            send_recovery(user)
            flash('Recovery email sent!', category='success')
            return redirect(url_for('auth.login'))

    return render_template('passwordRecov.html', user=current_user)


@auth.route('/reset_verified/<token>', methods=['GET', 'POST'])
def reset_password(token):

    user = User.verify_reset_token(token)

    if not user:
        flash(reset_token_expired, category='error')
        return redirect(url_for('auth.login'))

    password1 = request.form.get('password1')
    password2 = request.form.get('password2')

    if password1:
        if password1 == password2:
            print(check_password_hash(user.oldPassword, password1))

            if check_password_hash(user.oldPassword, password1):
                flash(cannot_reuse, category='error')
                return redirect(url_for('auth.reset_password', token=token))

            user.reset_password(password1, commit=True)
            flash('Password Reset Successful!!', category='success')
            return redirect(url_for('auth.login'))
        else:
            flash(mismatch_pw, category='error')

    return render_template('reset_verified.html', user=current_user)


# Method for admin dashboard
@auth.route('/adminPortal', methods=['GET', 'POST'])
@login_required
def adminPort():

    #qID = 0
    # Logic for updating accounts
    if request.method == 'POST':
        global SEARCHID
        SEARCHID = request.form.get('searchBar')
        if len(SEARCHID) < 1:
            flash(no_blank, category='error')
            return redirect(url_for('auth.adminPort'))
        else:
            return redirect(url_for('auth.accountOverview'))

    else:

        if current_user.hasAdmin:
            return render_template('adminPortal.html',
                                   user=current_user, query=User.query.all())
        else:
            flash(no_access, category='error')
            return redirect(url_for('views.home'))


@auth.route('/accountOverview', methods=['GET', 'POST'])
@login_required
def accountOverview():

    if current_user.hasAdmin:

        usr_status = False
        usr_hasMan = False
        usr_hasAdmin = False

        qID = int(SEARCHID)
        user_to_update = User.query.filter_by(id=qID).first()

        if request.method == 'POST':

            try:
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

                if len(firstName) < 2 or len(lastName) < 2 or len(email) < 1:
                    flash(no_blank, category='error')
                    return redirect(url_for('auth.accountOverview'))
                else:
                    userName = userNameGenGlobal(firstName, lastName)

                    updateStat = user_to_update.update_user(
                                    userName, email, firstName, 
                                    lastName, usr_hasMan, usr_hasAdmin, 
                                    usr_status, commit=True)

                if updateStat:
                    flash('Account updated successfully', category='success')
                    return redirect(url_for('auth.accountOverview'))
                else:
                    flash('Account Update Failed!', category='error')
                    
            #Using exception handling to determine the difference in POST requests. If a better alternative exists. Change ASAP
            except TypeError as err:
                #flash("TypeError: {0}".format(err), category='error')
                #return redirect(url_for('auth.accountOverview'))
                global ACC_ID
                ACC_ID = request.form.get('searchBar')
                return redirect(url_for('auth.view_account'))

    else:
        flash(no_access, category='error')
        return redirect(url_for('views.home'))    

    return render_template('accountOverview.html', user=current_user, 
                        query=User.query.all(), searchID=SEARCHID, 
                        acc_query = Account.query.join(User).filter(Account.user_id==SEARCHID))


#FORMAT monetary values to only use 2 decimal places by: 
#formated_float = "{:.2f}.format(float_variable)"
@auth.route('/newAccount', methods = ['GET', 'POST'])
@login_required
def newChart():


    qID = int(SEARCHID)
    
    if request.method == 'POST':
        acc_name = request.form.get('acc_name')
        acc_cat = request.form.get('acc_cat')
        acc_desc = request.form.get('acc_desc')
        init_bal = request.form.get('init_bal')
        acc_statement = request.form.get('acc_statement')
        
        new_acc = Account(acc_name = acc_name, acc_cat = acc_cat, 
                            acc_desc = acc_desc, init_bal = init_bal,
                            acc_statement = acc_statement, 
                            user_id = qID)
        
        db.session.add(new_acc)
        db.session.commit()
        return redirect(url_for('auth.accountOverview'))
    

    return render_template('newAccount.html', user = current_user, 
                        query = User.query.all(), 
                        searchID = SEARCHID)



@auth.route('/viewAccount', methods = ['GET', 'POST'])
@login_required
def view_account():

    #POST request to add entry into ledger--

    if request.method == 'POST':
        entry_desc = request.form.get('entry_desc')
        entry_cred = request.form.get('entry_cred')
        entry_deb = request.form.get('entry_deb')

        acc_id = int(ACC_ID)

        init_deb = float(entry_deb)
        init_cred = float(entry_cred)
        entry_bal = init_deb - init_cred
        
        new_entry = Ledger(acc_num = acc_id, entry_date=datetime.now(), entry_desc=entry_desc, entry_cred=entry_cred, entry_deb=entry_deb, entry_bal = entry_bal)
        db.session.add(new_entry)
        db.session.commit()

    
        prev_entry_num = new_entry.get_entry_num() - 1
        prev_entry = Ledger.query.filter_by(entry_num = prev_entry_num).first()
        prev_bal = ''
        if prev_entry:
            prev_bal = prev_entry.entry_bal

        
        if new_entry.entry_num == 1:
            new_entry.update_balance(entry_bal, commit=True)
        else:
            new_balance = format_balance(calculate_balance(prev_bal, entry_bal))
            new_entry.update_balance(new_balance, commit=True)
        
        
        return redirect(url_for('auth.view_account',legder_num = acc_id))


    return render_template('accountView.html', user = current_user, acc_ID = ACC_ID, 
                        acc_query = Account.query.join(User).filter(Account.user_id==SEARCHID),
                        led_query = Ledger.query.join(Account).filter(Ledger.acc_num==ACC_ID))

@auth.route('/help')
def help():
    return render_template("help.html", user=current_user)

@auth.route('/email_user', methods=['POST','GET'])
def send_email():
    user=current_user
    a = list()
    f = request.form
    for key in f.keys():
        for value in f.getlist(key):
            a.append(key)

    msg = Message(f'{a[1]}', sender=user.email, recipients=a[0])
    msg.body = a[2]
    msg.html = render_template('email_user.html', user=user)

    # there is an SMTP auth error here, Brandon you probably need to update your credentials
    try:
        mail.send(msg)
    except SMTPAuthenticationError:
        flash(email_error, category='error')
        return render_template('email_user.html', user=user)

# --Tools---

# Username generator
def userNameGenGlobal(first, last):
    currMonth = str(datetime.now().month)
    currYear = str(datetime.now().year)

    if len(currMonth) < 2:
        currMonth = '0' + currMonth

    userName = first[0] + last + currMonth + currYear[2] + currYear[3]
    return userName

def update_log_attempt(count):
    count +=1
    return count


def calculate_balance(prev_entry, curr_entry):
    return prev_entry + curr_entry


def format_balance(n):
        num = "{:,.2f}".format(n)
        return num

    
    



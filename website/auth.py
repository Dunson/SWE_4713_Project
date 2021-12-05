from os import error
from smtplib import SMTPAuthenticationError

from flask import Blueprint, render_template, request, flash, redirect, url_for
from sqlalchemy.orm import query
from .models import User, Account, Ledger, Error, EventLog
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, mail
from flask_login import login_user, login_required, logout_user, current_user
from .email import send_recovery
from datetime import datetime, timedelta
from flask_mail import Mail, Message
import json
auth = Blueprint('auth', __name__)
from sqlalchemy.sql import func

#GLOBAL Variables
SEARCHID = 'none'
ACC_ID = 'none'
LEDGER_NUM = 0
ATTEMPT_COUNT = 0
NOW = datetime.now()

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
acc_ufail = 'Account Update Failed!'
exceeded_att = 'You have exceeded maximum login attempts.'
unbalanced = 'Trial Balance does not balance to zero. Please check all ledger entries in accounts.'


def add_err_to_db(err):
    pass

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:

            if user.status == False:
                flash(not_activated, category='error')
                error = Error(error_desc=not_activated)
                db.session.add(error)
                error.errorcreate(not_activated, commit=True)
                return redirect(url_for('auth.login'))

            if user.hasAdmin == True and check_password_hash(user.password, password):
                flash('Admin login successful!', category='success')
                login_user(user)
                event = EventLog(creator=User.query.get(current_user.id).userName,
                                 event=f'User: {user.userName} logged in',
                                 event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
                db.session.add(event)
                db.session.commit()
                return redirect(url_for('auth.adminPort'))

            if check_password_hash(user.password, password):
                flash('Login Successful!', category='success')
                login_user(user)
                event = EventLog(creator=User.query.get(current_user.id).userName,
                                 event=f'User: {user.userName} logged in',
                                 event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
                db.session.add(event)
                db.session.commit()

                return redirect(url_for('views.home'))
            else:
                flash(ipw, category='error')
                error = Error(error_desc=ipw)
                db.session.add(error)
                error.errorcreate(ipw, commit=True)

            # Limits login attempts
            if check_password_hash(user.password, password):
                flash('Login Successful!', category='success')
                login_user(user)
                event = EventLog(creator=User.query.get(current_user.id).userName,
                                 event=f'User: {user.userName} logged in',
                                 event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
                db.session.add(event)
                db.session.commit()
                global ATTEMPT_COUNT
                ATTEMPT_COUNT = 0
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect Password! Attempt: ' + str(ATTEMPT_COUNT), category='error')
                ATTEMPT_COUNT += 1

            if ATTEMPT_COUNT > 3:
                flash('You have exceeded maximum login attempts. Your account has been deactivated.', category='error')
                User.deactivate_user(user, commit = True)
                return render_template('login.html', user=current_user, lpc=lpc())

        else:
            flash(fields_empty, category='error')
            error = Error(error_desc=fields_empty)
            db.session.add(error)
            error.errorcreate(fields_empty, commit=True)
    return render_template("login.html", user=current_user, lpc=lpc())


@auth.route('/logout')
@login_required
def logout():
    global ATTEMPT_COUNT
    ATTEMPT_COUNT = 0
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

        print(password_one, password_two)

        user_init = User()

        user = user_init.query.filter_by(email=email).first()
        pwd_check = user_init.password_check(password_one, password_two)

        # Creation validation logic
        if user:
            flash(acc_exists, category='error')
            error = Error(error_desc=acc_exists)
            db.session.add(error)
            error.errorcreate(acc_exists, commit=True)
        elif len(firstName) < 2:
            flash(gt_1_c, category='error')
            error = Error(error_desc=gt_1_c)
            db.session.add(error)
            error.errorcreate(gt_1_c, commit=True)
        elif password_one != password_two:  # This compares the two passwords
            flash(mismatch_pw, category='error')
            error = Error(error_desc=mismatch_pw)
            db.session.add(error)
            error.errorcreate(mismatch_pw, commit=True)
        elif not pwd_check:
            flash(does_not_meet_reqs, category='error')
            error = Error(error_desc=does_not_meet_reqs)
            db.session.add(error)
            error.errorcreate(does_not_meet_reqs, commit=True)
        else:
            # Add user to database
            new_user = User(email=email, firstName=firstName, lastName=lastName,
                            password=generate_password_hash(password_one, method='sha256'),
                            userName=userNameGenGlobal(firstName, lastName),
                            hasAdmin=False, hasMan=False, status=False,
                            creationDate=datetime.now(), expirationDate=datetime.now() + timedelta(days=365))
            event = EventLog(creator=User.query.get(current_user.id).userName, event=f'New user {userNameGenGlobal(firstName,lastName)} added',
                             event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
            db.session.add(event)
            db.session.add(new_user)
            db.session.commit()

            flash('Account Created! Note: The admininstrator must activate your account before you can login.', category='success')
            return redirect(url_for('auth.login'))

    return render_template("signUp.html", user=current_user, lpc=lpc())


@auth.route('/recovery', methods=['GET', 'POST'])
def recovery_Page():
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if email is in database
        user = User.query.filter_by(email=email).first()
        if not user:
            flash(email_not_found, category='error')
            error = Error(error_desc=email_not_found)
            db.session.add(error)
            error.errorcreate(email_not_found, commit=True)
        else:
            send_recovery(user)
            flash('Recovery email sent!', category='success')
            event = EventLog(creator=User.query.get(current_user.id).userName, event= f'Recovery email sent for {user.userName}',
                             event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
            db.session.add(event)
            db.session.commit()
            return redirect(url_for('auth.login'))

    return render_template('passwordRecov.html', user=current_user, lpc=lpc())


@auth.route('/reset_verified/<token>', methods=['GET', 'POST'])
def reset_password(token):

    user = User.verify_reset_token(token)

    if not user:
        flash(reset_token_expired, category='error')
        error = Error(error_desc=reset_token_expired)
        db.session.add(error)
        error.errorcreate(reset_token_expired, commit=True)
        return redirect(url_for('auth.login'))

    password1 = request.form.get('password1')
    password2 = request.form.get('password2')

    if password1:
        if password1 == password2:
            print(check_password_hash(user.oldPassword, password1))

            if check_password_hash(user.oldPassword, password1):
                flash(cannot_reuse, category='error')
                error = Error(error_desc=cannot_reuse)
                db.session.add(error)
                error.errorcreate(cannot_reuse, commit=True)
                return redirect(url_for('auth.reset_password', token=token))

            user.reset_password(password1, commit=True)
            flash('Password Reset Successful!', category='success')
            event = EventLog(creator=User.query.get(current_user.id).userName, event=f'Password reset for {user}',
                             event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
            db.session.add(event)
            db.session.commit()
            return redirect(url_for('auth.login'))
        else:
            flash(mismatch_pw, category='error')
            error = Error(error_desc=mismatch_pw)
            db.session.add(error)
            error.errorcreate(mismatch_pw, commit=True)

    return render_template('reset_verified.html', user=current_user, lpc=lpc())


# Method for admin dashboard
@auth.route('/adminPortal', methods=['GET', 'POST'])
@login_required
def adminPort():

    #qID = 0
    # Logic for updating accounts
    if request.method == 'POST':

        global SEARCHID
        SEARCHID = request.form.get('searchBar')

        if not SEARCHID:
            user_account_number = request.form.get("get_user")
            return redirect(url_for('auth.accountOverview', id=int(user_account_number)))

        if SEARCHID == None or len(SEARCHID) < 1:
            flash(no_blank, category='error')
            error = Error(error_desc=no_blank)
            db.session.add(error)
            error.errorcreate(no_blank, commit=True)
            return redirect(url_for('auth.adminPort'))
        else:
            return redirect(url_for('auth.accountOverview', id=SEARCHID))

    else:

        if current_user.hasAdmin or current_user.hasMan:
            return render_template('adminPortal.html',
                                   user=current_user, query=User.query.all(), lpc=lpc())
        else:
            flash(no_access, category='error')
            error = Error(error_desc=no_access)
            db.session.add(error)
            error.errorcreate(no_access, commit=True)
            return redirect(url_for('views.home'))


@auth.route('/accountOverview/<id>', methods=['GET', 'POST'])
@login_required
def accountOverview(id):


    if current_user.hasAdmin or current_user.hasMan:

        usr_status = False
        usr_hasMan = False
        usr_hasAdmin = False
        req = request.form

        # print(req.get("accOv"))

        qID = id
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
                    error = Error(error_desc=no_blank)
                    db.session.add(error)
                    error.errorcreate(no_blank, commit=True)
                    return redirect(url_for('auth.accountOverview'))
                else:
                    userName = userNameGenGlobal(firstName, lastName)

                    updateStat = user_to_update.update_user(
                                    userName, email, firstName, 
                                    lastName, usr_hasMan, usr_hasAdmin, 
                                    usr_status, commit=True)

                if updateStat:
                    flash('Account updated successfully', category='success')
                    event = EventLog(creator=User.query.get(current_user.id).userName, event=f'Account {userName} updated',
                                     event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
                    db.session.add(event)
                    db.session.commit()
                    return redirect(url_for('auth.accountOverview', id=id))
                else:
                    flash(acc_ufail, category='error')
                    error = Error(error_desc=acc_ufail)
                    db.session.add(error)
                    error.errorcreate(acc_ufail, commit=True)

            except TypeError as err:

                global ACC_ID
                ACC_ID = request.form.get('searchBar')
                if ACC_ID:
                    return redirect(url_for('auth.view_account', id=ACC_ID))

                account_number = request.form.get("get_account")
                if account_number:
                    return redirect(url_for('auth.view_account', id=int(account_number)))

                new_account = request.form.get('new_account')
                if new_account:
                    print(new_account)
                    return redirect(url_for('auth.newChart', id=int(new_account)))

    else:
        flash(no_access, category='error')
        error = Error(error_desc=no_access)
        db.session.add(error)
        error.errorcreate(no_access, commit=True)
        return redirect(url_for('views.home'))

    return render_template('accountOverview.html', user=current_user, query=User.query.all(),
                           searchID=id, acc_query=Account.query.join(User).filter(Account.user_id == id),
                            lpc=lpc())



@auth.route('/newAccount/<id>', methods = ['GET', 'POST'])
@login_required
def newChart(id):

    qID = id
    
    if request.method == 'POST':

        acc_name = request.form.get('acc_name')
        acc_cat = request.form.get('acc_cat')
        acc_desc = request.form.get('acc_desc')
        # init_bal = request.form.get('init_bal')
        acc_statement = request.form.get('acc_statement')
        
        new_acc = Account(acc_name=acc_name, acc_cat=acc_cat,
                            acc_desc=acc_desc, init_bal=0.00,
                            acc_statement=acc_statement,
                            user_id=qID)
        
        db.session.add(new_acc)
        event = EventLog(creator=User.query.get(current_user.id).userName, event='New Account added',
                         event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
        db.session.add(event)
        db.session.commit()
        return redirect(url_for('auth.accountOverview', id=id))
    

    return render_template('newAccount.html', user = current_user, 
                        query = User.query.all(), 
                        searchID = SEARCHID)




@auth.route('/accountView/<id>', methods = ['GET', 'POST'])
@login_required
def view_account(id):

    # POST request to add entry into ledger
    if request.method == 'POST':
        pr = request.form.get('pr')

        if pr:
            prq = Account.query.get(pr).user_id
            return redirect(url_for('auth.accountOverview', id=int(prq)))

        entry_desc = request.form.get('entry_desc')
        entry_cred = request.form.get('entry_cred')
        entry_deb = request.form.get('entry_deb')
        attachment = request.form.get('attachment')

        if not entry_cred:
            entry_cred = 0.00
        if not entry_deb:
            entry_deb = 0.00

        acc_id = id

        if attachment is None:
            attachment = "static/default.pdf"

        init_deb = float(entry_deb)
        init_cred = float(entry_cred)
        entry_bal = init_deb - init_cred

        new_entry = Ledger(entry_date=datetime.now(), entry_desc=entry_desc,
                           entry_cred=entry_cred, entry_deb=entry_deb, entry_bal=entry_bal,
                           isApproved='Pending', acc_num=acc_id, attachment=bytes(json.dumps(attachment), 'utf8'),
                           reject_comment="N/A")
        db.session.add(new_entry)
        event = EventLog(creator=User.query.get(current_user.id).userName, event='New Ledger entry added',
                         event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
        db.session.add(event)
        db.session.commit()

        new_balance = new_entry.calculate_balance()
        new_entry.update_balance(new_balance, commit=True)

        return redirect(url_for('auth.view_account', id=acc_id))

    return render_template('accountView.html', user=current_user, acc_id=id,
                        acc_query=Account.query.join(User).filter(Account.user_id == id),
                        led_query=Ledger.query.join(Account).filter(Ledger.acc_num == id,
                                                                    Ledger.isApproved == 'Approved'),
                        lpc=lpc())




@auth.route('/home')
def homepage():
    return render_template("home.html", user=current_user, acc_query=Account.query.join(User),
                           usracc=Account.query.join(User).filter(User.id == current_user.id), lpc=lpc())


@auth.route('/help')
def help():
    return render_template("help.html", user=current_user, lpc=lpc())


@auth.route('/email_user')
def e():
    return render_template("email_user.html", user=current_user, lpc=lpc())


@auth.route('/email_user', methods=['POST', 'GET'])
def send_email():

    if request.method == 'POST':
        user = current_user
        req = request.form
        e = req.get("e")
        s = req.get("s")
        b = req.get("b")

        print(e,s,b)

        msg = Message(f'{s}', sender=user.email, recipients=e)
        msg.body = b
        msg.html = render_template('email_user.html', user=user)

    # there is an SMTP auth error here, Brandon you probably need to update your credentials

        try:
            mail.send(msg)
            event = EventLog(creator=User.query.get(current_user.id).userName, event='Email sent',
                             event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
            db.session.add(event)
            db.session.commit()
        except SMTPAuthenticationError:
            flash(email_error, category='error')
            error = Error(error_desc=email_error)
            db.session.add(error)
            error.errorcreate(email_error, commit=True)
            flash("Emaill successfully sent, you may leave this page or send more emails.", category='Success')
            return render_template('email_user.html', user=user)

    return render_template('email_user.html', user=user, lpc=lpc())

@auth.route('/approvals', methods=['GET', 'POST'])
def approve():
    user = current_user
    req = request.form
    a = req.get("approve")
    r = req.get("reject")
    rc = req.get("reject_reasoning")

    if not rc:
        rc = "N/A"

    if request.method == "POST":
        if a:
            approval_query = Ledger.query.filter_by(entry_num=int(a)).first()
            approval_query.isApproved = 'Approved'
            event = EventLog(creator=User.query.get(current_user.id).userName, event='Ledger entry approved',
                             event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
            db.session.add(event)
        elif r:
            rejection_query = Ledger.query.filter_by(entry_num=int(r)).first()
            rejection_query.isApproved = 'Rejected'
            rejection_query.reject_comment = rc
            event = EventLog(creator=User.query.get(current_user.id).userName, event='Ledger entry rejected',
                             event_date=str(NOW.strftime("%Y-%m-%d, %H:%M:%S")))
            db.session.add(event)

        db.session.commit()

    return render_template('approvals.html', user=user, ledgerq=Ledger.query.filter_by(isApproved='Pending'),
                           rejected_entries=Ledger.query.filter_by(isApproved='Rejected'),
                           approved_entries=Ledger.query.filter_by(isApproved='Approved'),
                           all=Ledger.query.all(), lpc=lpc())


@auth.route('/income_statement/', methods=['GET','POST'])
def income_statement():
    id = current_user.id
    return render_template('income_statement.html', user=current_user, lpc=lpc())


@auth.route('/balance_sheet/', methods=['GET','POST'])
def balance_sheet():
    id = current_user.id

    select_id = 1
    if request.method == "POST":
        select_id = request.form.get("ian")
        redirect('auth.balance_sheet')

    accounts_list_by_user = Account.query.filter_by(user_id=select_id).all()
    accounts_list = Account.query.join(User).filter(Account.user_id == select_id).all()

    temp_arr = []
    for item in accounts_list_by_user:
        temp_arr.append(item)

    debit_accounts = [x for x in temp_arr if x.acc_cat == "Assets" or x.acc_cat == "Expenses" or x.acc_cat == "Equity"]
    credit_accounts = [x for x in temp_arr if x.acc_cat == "Revenue (income)"
                       or x.acc_cat == "Liabilities"
                       or x.acc_cat == "Other..."]

    assets_list = [x for x in debit_accounts if x.acc_cat == "Assets"]
    expenses_list = [x for x in debit_accounts if x.acc_cat == "Expenses"]
    equity_list = [x for x in debit_accounts if x.acc_cat == "Equity"]
    rev_list = [x for x in credit_accounts if x.acc_cat == "Revenue (income)"]
    liab_list = [x for x in credit_accounts if x.acc_cat == "Liabilities"]
    other_list = [x for x in credit_accounts if x.acc_cat == "Other..."]

    total_debits = 0
    for item in debit_accounts:
        total_debits += item.total(item.acc_num)

    total_credits = 0
    for item in credit_accounts:
        total_credits += item.total(item.acc_num)

    return render_template('balance_sheet.html', user=current_user, accounts_list=accounts_list,
                           acc_list_len=len(accounts_list), total_credits=total_credits, total_debits=total_debits,
                           assets_list=assets_list, expenses_list=expenses_list, equity_list=equity_list,
                           rev_list=rev_list, liab_list=liab_list, other_list=other_list,
                           ass_list_len=len(assets_list), exp_list=len(expenses_list), eq_list=len(equity_list),
                           rev_list_len=len(rev_list), lpc=lpc(), usrsel=User.query.get(select_id))


@auth.route('/trial_balance/', methods=['GET','POST'])
def trial_balance():
    id = current_user.id

    select_id = 1
    if request.method == "POST":
        select_id = request.form.get("ian")
        redirect('auth.trial_balance')

    account_list_by_cat = Account.query.filter_by(user_id=select_id).all()
    accounts_list = Account.query.join(User).filter(Account.user_id == select_id).all()

    temp_arr = []
    for item in account_list_by_cat:
        temp_arr.append(item.total(item.acc_num))

    creds = [x for x in temp_arr if x < 0]
    debs = [x for x in temp_arr if x > 0]


    if sum(creds) + sum(debs) != 0:
        flash(unbalanced, category="error")
        error = Error(error_desc=unbalanced)
        db.session.add(error)
        error.errorcreate(unbalanced, commit=True)
    else:
        flash("Trial Balance balances to 0!", category='success')

    return render_template('trial_balance.html', user=current_user,
                           accounts_list=Account.query.join(User).filter(Account.user_id == select_id),
                           temp_arr=temp_arr, creds=creds, debs=debs,
                           total_deb=sum(debs), total_cred=sum(creds), j=len(accounts_list),
                           lpc=lpc(), s=select_id, usrsel=User.query.get(select_id))


@auth.route('/event_log/', methods=['GET', 'POST'])
def evlog():
    evall = EventLog.query.all()
    return render_template('event_log.html', evall=evall, user=current_user, lpc=lpc())

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


def format_balance(float_variable):
    formated_float = '{:.2f}'.format(float_variable)
    return formated_float


def lpc():
    ledger_pending_count = db.session.query(Ledger).filter(Ledger.isApproved == 'Pending').all()
    lpc = len(ledger_pending_count)
    return lpc

 # Assets -- DEBIT
    # Expenses -- DEBIT
    # Liabilities -- CREDIT
    # Equity -- DEBIT
    # Revenue -- CREDIT
    # Other ... -- DOESNT MATTER

    # Assets -- DEBIT
    # Expenses -- DEBIT
    # Liabilities -- CREDIT
    # Equity -- DEBIT
    # Revenue -- CREDIT
    # Other ... -- DOESNT MATTER
from flask import Blueprint, render_template, request
from flask.helpers import url_for
from flask_login import login_required, current_user
from werkzeug.utils import redirect
from .models import User, Account, Ledger
from .auth import ACC_ID


views = Blueprint('views', __name__)

@views.route('/', methods =['GET', 'POST'])
@login_required
def home():

    if request.method == 'POST':
        global ACC_ID
        ACC_ID = request.form.get('searchBar')
        return redirect(url_for('auth.view_account'))

    return render_template("home.html", user=current_user,  acc_query=Account.query.join(User))

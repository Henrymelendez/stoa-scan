from datetime import datetime, timezone
from flask import render_template, redirect, flash, url_for, request, g, current_app
from flask_login import current_user, login_required
import sqlalchemy as sa
from app import db
from app.main.forms import EditProfileForm
from app.models import User
from app.main import bp


@bp.route('/')
@bp.route('/index')
@login_required
def index():
    user = {'username': 'Henry'}
    return render_template('index.html', title='Home', user=user)

@bp.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_login = datetime.now(timezone.utc)
        db.session.commit()

@bp.route('/user/<username>')
@login_required
def user(username):
    user = db.session.scalar(sa.select(User).where(User.username == username))
    if user is None:
        flash('User not found.')
        return redirect(url_for('index'))
    return render_template('user.html', user=user)


@bp.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(original_firstname=current_user.first_name, original_lastname=current_user.last_name)
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)
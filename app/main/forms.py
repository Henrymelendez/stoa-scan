from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, ValidationError
import sqlalchemy as sa
from app import db
from app.models import User
from flask import request

class EditProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])  # Changed from firstName
    last_name = StringField('Last Name', validators=[DataRequired()])    # Changed from lastname
    submit = SubmitField('Submit')

    def __init__(self, original_firstname, original_lastname, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_firstname = original_firstname
        self.original_lastname = original_lastname

    def validate_first_name(self, first_name):  # Updated method name
        if self.first_name.data != self.original_firstname:
            user = db.session.scalar(sa.select(User).where(
                User.first_name == first_name.data))
            if user is not None:
                raise ValidationError('Please use a different first name.')

    def validate_last_name(self, last_name):  # Updated method name
        if self.last_name.data != self.original_lastname:
            user = db.session.scalar(sa.select(User).where(
                User.last_name == last_name.data))
            if user is not None:
                raise ValidationError('Please use a different last name.')
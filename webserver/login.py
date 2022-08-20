from . import app
from .dataconnector import LoginUser

from flask_login import LoginManager
from wtforms import Form, StringField, IntegerField, BooleanField, SelectMultipleField, PasswordField, FileField, \
    DateTimeLocalField, TextAreaField, FloatField, SelectField, SubmitField
from wtforms.validators import *

login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    return LoginUser.query.get(int(user_id))


class LoginForm(Form):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

    remember_me = BooleanField('Remember me')


class RegisterForm(Form):
    username = StringField('Your username', [InputRequired(), Length(min=4, max=25)])
    password = PasswordField('Your password', [InputRequired(), Length(min=4, max=25), EqualTo('confirm')])
    confirm = PasswordField('Repeat your password', [])

    name = StringField('Name', [InputRequired()])
    surname = StringField('Surname', [InputRequired()])


class ChangePasswordForm(Form):
    old_password = PasswordField('Old password', [InputRequired(), Length(min=4, max=25)])
    new_password = PasswordField('New password', [InputRequired(), Length(min=4, max=25), EqualTo('confirm')])
    confirm = PasswordField('Repeat new password', [InputRequired(), Length(min=4, max=25)])


class ChangePersonalDataForm(Form):
    name = StringField('First Name', [InputRequired(), Length(min=4, max=25)])
    surname = StringField('Last Name', [InputRequired(), Length(min=4, max=25)])


class CoffeeForm(Form):
    name = StringField('Name', [InputRequired(), Length(min=4, max=25)])
    description = TextAreaField('Description', [Length(max=300)])
    price = FloatField('Price', [InputRequired(), NumberRange(min=0)])
    photo = FileField('Photo')
    is_available = BooleanField('Available')


class UserForm(Form):
    id = IntegerField('id')
    username = StringField('Username', [InputRequired()])

    balance = FloatField('Balance', [InputRequired()])
    is_admin = BooleanField('Is Admin')
    is_active = BooleanField('Is Active')
    name = StringField('Name', [InputRequired()])
    surname = StringField('Surname', [InputRequired()])
    date_created = DateTimeLocalField('Date Created')


class HistorySearchForm(Form):
    date_from = DateTimeLocalField('Date From', format=['%Y-%m-%dT%H:%M'])
    date_to = DateTimeLocalField('Date To', format=['%Y-%m-%dT%H:%M'])

    user_made = SelectField('User made', default=None, coerce=int)
    coffee = SelectField('Coffees', default=None, coerce=int)



def init():
    login_manager.init_app(app)

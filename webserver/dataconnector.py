import uuid

from . import app

from werkzeug.security import generate_password_hash

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

import os

db = SQLAlchemy()


class LoginUser(UserMixin, db.Model):
    __tablename__ = 'login_users'

    id = db.Column(db.Integer, nullable=False, autoincrement=True, primary_key=True)
    username = db.Column(db.VARCHAR(25), unique=True, nullable=False)
    password = db.Column(db.VARCHAR(110), nullable=False)

    balance = db.Column(db.Integer, nullable=False, default=25.)

    is_admin = db.Column(db.Boolean, default=False)
    _is_active = db.Column(db.Boolean, name='is_active', default=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    made_coffees = db.relationship('Coffee', backref=db.backref('user_made'))

    @property
    def is_active(self):
        return self._is_active

    @is_active.setter
    def is_active(self, val):
        self._is_active = val


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, db.ForeignKey('login_users.id'), primary_key=True)
    login_user = db.relationship('LoginUser',  backref=db.backref('user', uselist=False))

    name = db.Column(db.String(20), nullable=False)
    surname = db.Column(db.String(20), nullable=False)


class CoffeeItem(db.Model):
    __tablename__ = 'menu'

    id = db.Column(db.Integer, nullable=False, autoincrement=True, primary_key=True)
    name = db.Column(db.String(30), nullable=False, unique=True)
    description = db.Column(db.String(300), nullable=False)
    price = db.Column(db.Float, nullable=False)
    photo = db.Column(db.VARCHAR(45), nullable=False)
    is_available = db.Column(db.Boolean, default=1)

    made_coffees = db.relationship('Coffee', backref=db.backref('coffee'))


class Coffee(db.Model):
    __tablename__ = 'history'

    code = db.Column(db.String(37), nullable=False, primary_key=True, default=uuid.uuid4)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    status = db.Column(db.Integer, default=0)

    price = db.Column(db.Float, nullable=False)

    coffee_id = db.Column(db.Integer, db.ForeignKey('menu.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('login_users.id'))


def init():
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('CLEARDB_DATABASE_URL').split('?')[0]
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = SQLALCHEMY_ENGINE_OPTIONS
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    with app.app_context():
        db.create_all(app=app)

        if not LoginUser.query.filter(LoginUser.username == 'admin').first():
            admin_person = User(
                name='Mykyta',
                surname='Yezhykhin'
            )
            admin = LoginUser(
                username='admin',
                password=generate_password_hash('admin'),
                is_admin=True,
                user=admin_person
            )
            db.session.add(admin)

            user_person = User(
                name='User',
                surname='Test'
            )
            user = LoginUser(
                username='user',
                password=generate_password_hash('user'),
                user=user_person
            )
            db.session.add(user)

        if not CoffeeItem.query.first():
            coffee_item = CoffeeItem(
                name='Latte',
                description='Latte is one of the most popular and ancient drinks in the world. Millions of people start their day with a latte.',
                price=1.5,
                photo='latte-small.jpg'
            )
            db.session.add(coffee_item)

        db.session.commit()


def close_conn():
    db.close_all_sessions()
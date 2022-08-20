import io
import os
import uuid

import boto3
from botocore.client import Config

from flask import request, render_template, flash, redirect, url_for, send_file
from flask_login import login_user, current_user, logout_user, login_required

from pandas import DataFrame

from functools import wraps

from werkzeug.security import generate_password_hash, check_password_hash
import werkzeug.utils

import time

from . import app, web, api, account, admin
from .login import LoginForm, RegisterForm, login_manager, ChangePasswordForm, ChangePersonalDataForm, CoffeeForm, \
    UserForm, HistorySearchForm
from .dataconnector import LoginUser, CoffeeItem, Coffee, User, db

reports_dict = {}
img_urls = {}

access_key = os.getenv('AWS_ACCESS_KEY')
secret_key = os.getenv('AWS_SECRET_KEY')
bucket_name = os.getenv('BUCKET_NAME')

client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                      config=Config(region_name='eu-central-1', signature_version='s3v4'),
                      endpoint_url='https://s3.eu-central-1.amazonaws.com')


@app.route('/static/coffeeimgs/<img_name>')
def send_img(img_name):
    url = img_urls.get(img_name)
    if url and time.time() - url[1] < 100:
        return redirect(url[0])

    url = client.generate_presigned_url('get_object', Params={'Bucket': bucket_name, 'Key': img_name}, ExpiresIn=100)
    img_urls[img_name] = (url, time.time())
    return redirect(url)


@web.route('/')
def index():
    menu = CoffeeItem.query.filter_by(is_available=True).all()

    return render_template("home.html", menu=menu)


@web.route('/about')
def about():
    return render_template('about.html')


@web.route('/register', methods=['get', 'post'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('web.index'))

    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        hashed_pass = generate_password_hash(form.password.data)
        new_user = LoginUser(username=form.username.data, password=hashed_pass)
        if LoginUser.query.filter_by(username=new_user.username).first():
            form.username.errors.append('This username is allready taken')
            return render_template('auth/register.html', form=form)

        new_user.user = User(name=form.name.data, surname=form.surname.data)

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('web.index'))

    return render_template('auth/register.html', form=form)


@web.route('/login', methods=['get', 'post'])
def login():
    error = 'error' in request.args
    if request.method == 'GET' and current_user.is_authenticated:
        return redirect(url_for('web.index'))
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = LoginUser.query.filter_by(_is_active=True, username=form.username.data).first()
        if not user or not check_password_hash(user.password, form.password.data):
            flash('Please check your login details and try again.')
            return redirect(url_for('web.login'))

        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('web.index'))

    return render_template("auth/login.html", form=form, error=error)


@web.route('/logout', methods=['get', 'post'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('web.index'))


@web.route('/buy/<coffee_id>', methods=['get', 'post'])
@login_required
def buy(coffee_id):
    item: CoffeeItem = CoffeeItem.query.filter(CoffeeItem.is_available).filter(CoffeeItem.id == coffee_id).first()
    if not item:
        return redirect('/')
    if request.method == 'GET':
        return render_template("buy.html", item=item)
    else:
        if item.price > current_user.balance:
            return render_template("buy.html", error="Please top up your balance", item=item)

        current_user.balance -= item.price
        time.sleep(2)
        new_coffee = Coffee(coffee_id=item.id, user_id=current_user.id, price=item.price)
        db.session.add(new_coffee)
        db.session.commit()

        return redirect(f'/coffee/status/{new_coffee.code}')


@web.route('/coffee/status/<coffee_uuid>')
def coffee_status(coffee_uuid):
    coffee = Coffee.query.get(coffee_uuid)

    item = coffee.coffee if coffee else None
    if not coffee:
        return redirect('/')

    return render_template('coffee_status.html', coffee=coffee, item=item)


@web.route('/history')
@login_required
def myhistory():
    history = Coffee.query.filter_by(user_made=current_user).order_by(Coffee.date.desc()).all()

    return render_template('history.html', history=history)


@account.route('/')
@login_required
def account_index():
    return render_template('account/account.html')


@account.route('/change/password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        if check_password_hash(current_user.password, form.old_password.data):
            current_user.password = generate_password_hash(form.new_password.data)

            db.session.commit()

        return redirect('/account')

    return render_template("account/change_password.html", form=form)


@account.route('/change/personal_data', methods=['get', 'post'])
@login_required
def change_personal_data():
    form = ChangePersonalDataForm(request.form)

    if not request.form:
        form.name.data = current_user.user.name
        form.surname.data = current_user.user.surname

    if request.method == 'POST' and form.validate():
        current_user.user.name = form.name.data
        current_user.user.surname = form.surname.data

        db.session.commit()

        return redirect('/account')

    return render_template('account/change_personal_data.html', form=form)


@account.route('/topup/<balance>')
@login_required
def topup_balance(balance):
    current_user.balance += int(balance)

    db.session.commit()

    return redirect('/account')


def admin_required(func):
    @wraps(func)
    def wraper(*args, **kwargs):
        if current_user.is_authenticated:
            if not current_user.is_admin:
                return redirect('/')
            return func(*args, **kwargs)
        else:
            return redirect('/login?error=1')

    return wraper


@admin.route('/')
@admin_required
def admin_index():
    return render_template('admin/admin_index.html')


@admin.route('/total_history', methods=['get', 'post'])
@admin_required
def admin_total_history():
    form = HistorySearchForm(request.form)
    history = Coffee.query.order_by(Coffee.date.desc())
    users = LoginUser.query.order_by(LoginUser.id)
    coffees = CoffeeItem.query.order_by(CoffeeItem.id)
    if request.method == 'POST':
        if form.date_from.data:
            history = history.filter(Coffee.date >= form.date_from.data)
        if form.date_to.data:
            history = history.filter(Coffee.date <= form.date_to.data)
        if form.user_made.data:
            history = history.filter(Coffee.user_id == form.user_made.data)
            users = users.filter(LoginUser.id == form.user_made.data)
        if form.coffee.data:
            history = history.filter(Coffee.coffee_id == form.coffee.data)
            coffees = coffees.filter(Coffee.coffee_id == form.coffee.data)

    history = history.all()
    users = users.all()
    coffees = coffees.all()

    history_df = DataFrame([(row.date, row.coffee.name, row.coffee.price, row.user_made.user.name + ' ' + row.user_made.user.surname,
                             row.user_made.username) for row in history],
                           columns=('Date', 'Pruct Name', 'Price ($)', 'User Full Name', 'Username'))
    reports_dict[current_user.id] = history_df

    form.coffee.choices = [(0, '')] + [(coffee.id, coffee.name) for coffee in coffees]
    form.user_made.choices = [(0, '')] + [(user.id, user.user.surname + ' ' + user.user.name) for user in users]

    return render_template('admin/total_history.html', history=history, form=form)


@admin.route('/report')
@admin_required
def reports():
    report = reports_dict.get(current_user.id)

    if report is None:
        return redirect('/admin/total_history')

    report_file = io.BytesIO()
    report.to_excel(report_file, index=False)
    report_file.seek(0)
    return send_file(report_file, download_name='report.xlsx', as_attachment=True)


@admin.route('/coffees')
@admin_required
def all_coffees():
    coffees = CoffeeItem.query.order_by(CoffeeItem.id).all()

    return render_template('admin/all_coffees.html', menu=coffees)


@admin.route('/coffees/<coffee_id>/change_state')
@admin_required
def delete_coffee(coffee_id):
    coffee_item = CoffeeItem.query.get(coffee_id)
    coffee_item.is_available = not coffee_item.is_available

    db.session.commit()

    return redirect('/admin/coffees')


@admin.route('/coffees/<coffee_id>/edit', methods=['get', 'post'])
@admin_required
def coffee_edit(coffee_id):
    coffee_item = CoffeeItem.query.get(coffee_id)

    form = CoffeeForm(request.form)

    if request.method == 'GET':
        form.name.data = coffee_item.name
        form.description.data = coffee_item.description
        form.price.data = coffee_item.price
        form.photo.data = coffee_item.photo
        form.is_available.data = coffee_item.is_available

    if request.method == 'POST' and form.validate():
        coffee_item.name = form.name.data
        coffee_item.description = form.description.data
        coffee_item.price = form.price.data
        coffee_item.is_available = form.is_available.data

        if 'photo' in request.files and request.files['photo'].filename:
            file = request.files['photo']

            file_type = file.filename.split('.')[-1]
            file_type = werkzeug.utils.secure_filename(file_type)
            file_name = str(uuid.uuid4()) + '.' + file_type
            if file_type not in ['jpg', 'jpeg', 'png', 'jpe']:
                form.photo.errors.append('You must send image only')

                return render_template('admin/coffee_profile.html', form=form, edit=True)

            client.upload_fileobj(file, bucket_name, file_name)

            coffee_item.photo = file_name

        db.session.commit()

        return redirect(f'/admin/coffees')

    return render_template('admin/coffee_profile.html', form=form, edit=True)


@admin.route('/coffees/<coffee_id>')
@admin_required
def coffee_page(coffee_id):
    coffee_item = CoffeeItem.query.get(coffee_id)

    form = CoffeeForm()

    form.name.data = coffee_item.name
    form.description.data = coffee_item.description
    form.price.data = coffee_item.price
    form.photo.data = coffee_item.photo
    form.is_available.data = coffee_item.is_available

    return render_template('admin/coffee_profile.html', form=form, edit=False)


@admin.route('/coffees/add', methods=['get', 'post'])
@admin_required
def add_coffee():
    form = CoffeeForm(request.form)

    if request.method == 'POST' and form.validate():
        if not request.files:
            form.photo.errors.append('You must sent an image file')

            return render_template('admin/add_coffee.html', form=form)

        file = request.files['photo']
        file_type = file.filename.split('.')[-1]
        file_type = werkzeug.utils.secure_filename(file_type)
        file_name = str(uuid.uuid4()) + '.' + file_type
        if file_type not in ['jpg', 'jpeg', 'png', 'jpe']:
            form.photo.errors.append('You must sent image only')

            return render_template('admin/add_coffee.html', form=form)

        try:
            client.upload_fileobj(file, bucket_name, file_name)
            # file.save(app.root_path + fr'\static\coffeeimgs\{file_name}')
        except:
            form.photo.errors.append('System can"t save your file')

            return render_template('admin/add_coffee.html', form=form)

        new_coffee = CoffeeItem(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data,
            photo=file_name
        )

        db.session.add(new_coffee)
        db.session.commit()

        return redirect('/admin/coffees')

    return render_template('admin/add_coffee.html', form=form)


@admin.route('/users')
@admin_required
def all_users():
    users = LoginUser.query.order_by(LoginUser.date_created).all()

    return render_template('admin/all_users.html', users=users)


@admin.route('/users/<user_id>')
@admin_required
def get_user(user_id):
    user = LoginUser.query.get(user_id)
    form = UserForm()

    form.username.data = user.username
    form.balance.data = user.balance
    form.is_admin.data = user.is_admin
    form.is_active.data = user.is_active
    form.name.data = user.user.name
    form.surname.data = user.user.surname
    form.id.data = user.id

    form.date_created.data = user.date_created

    return render_template('admin/user.html', form=form, edit=False)


@admin.route('/users/<user_id>/edit', methods=['get', 'post'])
@admin_required
def edit_user(user_id):
    user = LoginUser.query.get(user_id)
    form = UserForm(request.form)

    form.date_created.data = user.date_created

    if request.method == "GET":
        form.username.data = user.username
        form.balance.data = user.balance
        form.is_admin.data = user.is_admin
        form.is_active.data = user.is_active
        form.name.data = user.user.name
        form.surname.data = user.user.surname
        form.id.data = user.id

    if request.method == 'POST' and form.validate():
        user.username = form.username.data
        user.balance = form.balance.data
        user.is_admin = form.is_admin.data
        user.is_active = form.is_active.data
        user.user.name = form.name.data
        user.user.surname = form.surname.data

        db.session.commit()

        return redirect('/admin/users')

    return render_template('admin/user.html', form=form, edit=True)


@login_manager.unauthorized_handler
def unauth():
    return redirect('/login?error=1')


def init():
    app.config["SECRET_KEY"] = "lP5iU2RirlTf6iBjfnGYBH2CHJBh39dPurXWjlAD"
    app.ssl_context = 'adhoc'

    app.register_blueprint(web)
    app.register_blueprint(api)
    app.register_blueprint(admin)
    app.register_blueprint(account)
    # app.debug = True


def stop():
    client.close()

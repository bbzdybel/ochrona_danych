import hashlib
import json
import os
from time import time
import jwt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from flask_mail import Mail, Message
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm, form
from werkzeug.debug import console
from wtforms import StringField, PasswordField, BooleanField, EmailField
from wtforms.validators import InputRequired, Email, Length, DataRequired, ValidationError
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from base64 import b64encode, b64decode
from bs4 import BeautifulSoup

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
pepper = b'dfwiubwiubdvbwdbwdvbwuvwdvb'
salt_passManager = b'bardzotajnasoldomieszaniahasel'
encryption_method = 'pbkdf2:sha256:100000'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\zdybe\\Desktop\\OD\\ochrona_danych\\ODFlask_proj\\finish\\database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.mailtrap.io'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = "9089f97df84c67"
app.config['MAIL_PASSWORD'] = "1a81aa0531dd79"
mail = Mail(app)


bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    salt = db.Column(db.String(32))
    passManager = db.relationship("PassManager", backref='user', lazy=True)
    passwords_key = db.Column(db.String(80))

    def __repr__(self):
        return f" Id: {self.id} \n Username: {self.username} \n Email: {self.email} \n Password: {self.password} \n"

    def get_reset_token(self, expires=500):
        return jwt.encode({'reset_password': self.username, 'exp': time() + expires},
                          key=app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_token(token):
        try:
            username = jwt.decode(token, key=app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except Exception as e:
            print(e)
            return
        return User.query.filter_by(username=username).first()


class PassManager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appName = db.Column(db.String(15), unique=True)
    login = db.Column(db.String(50))
    password = db.Column(db.String(80))
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, appName,login,password, userId):
        self.appName = appName
        self.login = login
        self.password = password
        self.userId = userId

class ForgotForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email(message='Invalid email'), Length(max=50)])

class PasswordResetForm(FlaskForm):
    new_password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=80)])
    confirm = PasswordField('Repeat Password')


def pad_data(data):
    n = AES.block_size - (len(data) % AES.block_size) - 1
    data += b'\x80'
    data += b'\x00' * n
    return data


def prevent_js(data):
    if bool(BeautifulSoup(data, "html.parser").find()):
        return ""
    else:
        return data


@app.route('/insert', methods=['POST'])
@login_required
def insert():

    if request.method == 'POST':

        userPasswordFromDash = prevent_js(request.form['password_user'])
        user = User.query.filter_by(username=current_user.username).first()
        if user:
            if hashlib.pbkdf2_hmac('sha256', userPasswordFromDash.encode('utf-8'), user.salt + pepper, 100000) == (
            user.password):
                passwordFromDash = encrypt_value(pad_data(userPasswordFromDash.encode()), prevent_js(request.form['password']))
                webappFromDash = prevent_js(request.form['webapp'])
                loginFromDash = prevent_js(request.form['login'])
                if not webappFromDash or not loginFromDash or not passwordFromDash:
                    return redirect(url_for('dashboard'))
                else:
                    my_data = PassManager(webappFromDash, loginFromDash, passwordFromDash, user.id)
                    db.session.add(my_data)
                    db.session.commit()
                    flash("Added new password")
                    return redirect(url_for('dashboard'))

        return redirect(url_for('dashboard'))


@app.route('/update', methods = ['GET', 'POST'])
@login_required
def update():
    if request.method == 'POST':

        userPasswordFromDash = prevent_js(request.form['password_for_the_app'])
        user = User.query.filter_by(username=current_user.username).first()
        if user:
            if hashlib.pbkdf2_hmac('sha256', userPasswordFromDash.encode('utf-8'), user.salt + pepper, 100000) == (
                    user.password):

                my_data = PassManager.query.get(request.form.get('id'))
                my_data.appName = prevent_js(request.form['webapp'])
                my_data.login = prevent_js(request.form['login'])
                password_before_checking = prevent_js(request.form['password'])

                if not my_data.appName or not my_data.login or not password_before_checking:
                    return redirect(url_for('dashboard'))
                else:
                    my_data.password = encrypt_value(pad_data(userPasswordFromDash.encode()),
                                                     password_before_checking)
                    db.session.commit()
                    flash("Passoword Updated Successfully")

        return redirect(url_for('dashboard'))


@app.route('/delete/<id>/', methods=['GET', 'POST'])
@login_required
def delete(id):
    userID = current_user.id
    try:
        my_data = PassManager.query.get(id)
        if my_data.userId == userID:
            db.session.delete(my_data)
            db.session.commit()
            flash("Password Deleted Successfully")
    except ValueError:
        flash("Password Deleted Unsuccessfully")

    return redirect(url_for('dashboard'))


@app.route('/deciferpass', methods = ['GET', 'POST'])
@login_required
def deciferpass():

    if request.method == 'POST':
        userPasswordFromDash = request.form['password_to_the_app']
        user = User.query.filter_by(username=current_user.username).first()
        if user:
            if hashlib.pbkdf2_hmac('sha256', userPasswordFromDash.encode('utf-8'), user.salt + pepper, 100000) == (
                    user.password):
                if not prevent_js(request.form['password']):
                    return redirect(url_for('dashboard'))
                else:
                    passwordFromDash = decrypt_value(pad_data(userPasswordFromDash.encode()), request.form['password'])
                    flash("Your password to these WebApp is: " + passwordFromDash)
                    return redirect(url_for('dashboard'))

        return redirect(url_for('dashboard'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def check_username(form, field):
    user = User.query.filter_by(username=form.username.data).first()
    if user:
        raise ValidationError("Username Taken")


def check_email(form, field):
    user = User.query.filter_by(email=form.email.data).first()
    if user:
        raise ValidationError("Email already registered")

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50), check_email])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15), check_username])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if hashlib.pbkdf2_hmac('sha256', form.password.data.encode('utf-8'), user.salt + pepper, 100000) == (user.password):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))


        return '<h1>Invalid username or password</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        salt = os.urandom(32)
        hashed_password = hashlib.pbkdf2_hmac('sha256', form.password.data.encode('utf-8'), salt + pepper, 100000)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, salt=salt, passwords_key=get_key(16))
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


def get_key(size):
    key = os.urandom(size)
    return key


@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.filter_by(username=current_user.username).first()
    passwod_list = user.passManager
    visible_passwords_list = []

    for item in passwod_list:
        visible_passwords_list.append(
            {'id': item.id, 'appName': item.appName, 'login':  item.login,
             'password': item.password})

    return render_template('dashboard.html', visible_passwords_list = visible_passwords_list)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/reset_verified/<token>', methods=['GET', 'POST'])
def reset_verified(token):

    form = PasswordResetForm()

    if form.validate_on_submit():
        user = User.verify_reset_token(token)
        if not user:
            return redirect(url_for('index'))

        method, salt, hash = generate_password_hash(form.new_password.data + pepper, method=encryption_method,
                                                    salt_length=24).split('$')
        hashed_password = salt + '$' + hash
        user.password = hashed_password
        db.session.commit()
        flash('Password changed successfully!')
        return redirect(url_for('login'))

    return render_template('reset_verified.html', form=form)

def send_email(user):
    token = user.get_reset_token()

    msg = Message()
    msg.subject = "Password Reset"
    msg.sender = app.config['MAIL_USERNAME']
    msg.recipients = [user.email]
    msg.html = render_template('reset_your_password.html', user=user, token=token)

    mail.send(msg)

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    form = ForgotForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            send_email(user)

        flash('You will receive an email, if we find you in our databse.')
        return redirect(url_for('index'))

    return render_template('forgot.html', form=form)


def encrypt_value(key, data_to_encrypt):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data_to_encrypt.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct })
    return result


def decrypt_value(key, data_to_decrypt):
    data_to_decrypt = json.loads(data_to_decrypt)
    iv = b64decode(data_to_decrypt['iv'])
    ct = b64decode(data_to_decrypt['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('C:\\Users\\zdybe\\Desktop\\OD\\ochrona_danych\\ODFlask_proj\\finish\\ssl\\cert.pem', 'C:\\Users\\zdybe\\Desktop\\OD\\ochrona_danych\\ODFlask_proj\\finish\\ssl\\key.pem'))

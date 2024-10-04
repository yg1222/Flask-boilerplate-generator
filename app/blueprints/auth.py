from flask import Flask, current_app, render_template, redirect, request, jsonify, url_for, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, \
    current_user, logout_user
from  app.forms import LoginForm, SignupForm, ForgotPasswordForm, ResetPasswordForm
from nh3 import clean
import app.functions as functions
from app.database import db, Account, User
from app.functions import url_has_allowed_host_and_scheme
import json
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import uuid

from flask import Blueprint
auth = Blueprint('auth', __name__)


current_year = datetime.now().year
login_request_count = {}
signup_request_count = {}


@auth.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    now = datetime.utcnow()

    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    if request.method == "POST":
        response = {'redirect': None, 
                    'message': '',
                    'authenticated': False,
                    'code':103}

        form_data = request.get_json()
        form = LoginForm(data=form_data) 
        if form.validate():
            if form.disappearing_info.data: 
                logging.warning(f"Honeypot triggered. Possible bot submission: {form_data}")
                return {'redirect': None, 
                        'message': 'Your submission was not processed. Please try again.',
                        'authenticated': False, 'code':111}
                            
            # Login and validate the user.
            # user should be an instance of your `User` class
            email = clean(form_data.get("email")).lower().strip()
            password = clean(form_data.get("password"))
            
            user = User.query.filter_by(email=email).first()
            if user:
                if user.is_locked_out():
                    response['message'] = 'Account is locked. Try again later.'
                    return jsonify(response)
                if user.is_verified == False:
                    response['message'] = 'Email verification required. Please check your email.'
                    send_verification_email(user, 'email')
                    return jsonify(response)
                auth_response = functions.authenticate_and_login(email, password)
                if auth_response:
                    response['redirect'] = '/'
                    response['message'] = 'success'
                    response['authenticated']= auth_response
                    response['code'] = 101
                    next = request.args.get('next')
                    if next and url_has_allowed_host_and_scheme(next, request.host):
                        response['redirect'] = next
                else:
                    if user.is_locked_out():
                        response['message'] = 'Too many failed attempts. Account locked. Try later.'
                    else:
                        response['message'] = 'Incorrect email or password.'

            return jsonify(response)

        response['message'] = 'Invalid submission. Please correct errors and try again.'
        return jsonify(response)
        
    else:
        if current_user.is_authenticated:
            return render_template("index.html")
        else:
            return render_template("login.html", form=LoginForm())

@auth.route("/logout", methods = ['GET', 'POST'])
def logout():
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # send reset link to the email address
    if request.method == 'POST':
        logging.debug("FORGOT P")
        form_data = request.get_json()
        form = LoginForm(data=form_data)
        logging.debug(form_data)
        if form.disappearing_info.data:
            logging.warning(f"Honeypot triggered. Possible bot submission: {form_data}")
            return {'redirect': None, 
                    'message': 'Your submission was not processed. Please try again.',
                    'authenticated': False, 'code':111}
        else:
            email = clean(form_data.get("email")).lower().strip()
            user = User.query.filter_by(email=email).first()
            if user:
                send_verification_email(user, 'password')
            return jsonify({'redirect': None, 
                    'message': 'A password reset link has been sent to your email.',
                    'authenticated': False, 'code':101})


def send_verification_email(user, action):
    """
    Generates tokens and sends emailverification or password reset emails

    :param obj user: The user object
    :param str action: 'email' sends an email verification email,
    'password' sends a password reset email
    """
    try:
        user.generate_verification_token()
        email = user.email
        token= user.verification_token
        url = url_for('auth.verify', action=action, token=token, _external=True)
        html, body, subject = None, None, None
        site_name='Logisco'
        if action == 'email':
            subject="Please Verify Your Email Address"
            html=render_template('email_verification.html', site_name=site_name, user=user, url=url)
            body=render_template('email_verification.txt', site_name=site_name, user=user, url=url)
        else:
            subject="Password Reset"
            html=render_template('password_email.html', site_name=site_name, user=user, url=url)
            body=render_template('password_email.txt', site_name=site_name, user=user, url=url)

        functions.send_mail(subject=subject, recipient=email, body=body, html=html)
    except AttributeError as e:
        logging.error(f"Invalid user object in send_verification_email(): {e}")
    except Exception as e:
        logging.error(e)


@auth.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        form_data = request.get_json()
        logging.debug(form_data)
        form = ResetPasswordForm(data=form_data) 
        if form.validate():
            logging.debug("form validated")
            if form.disappearing_info.data: 
                logging.warning(f"Honeypot triggered. Possible bot submission: {form_data}")
                return {'redirect': None, 
                        'message': 'Your submission was not processed. Please try again.',
                        'authenticated': False, 'code':111}


            new_password = form_data.get("new_password")
            confirm_password = form_data.get("confirm_password")
            user = User.query.filter_by(verification_token=token).first()
            if user and new_password == confirm_password:
                user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)
                user.verification_token = None
                db.session.add(user)
                db.session.commit()
                login_user(user)
                return jsonify({
                    'code': 101,
                    'message': "Success. Your password was updated.",
                    'redirect': '/',
                    'authenticated': True}
                )
            else:
                return jsonify({
                    'code': 103,
                    'message': "Invalid or expired token. Another one has been sent to you. Check your email.",
                    'redirect': None,
                    'authenticated': False})
        
        return jsonify({
            'code': 103,
            'message': "Error. Unable to update your password. Please try again.",
            'redirect': None,
            'authenticated': False}
        ) 
    return render_template("reset_password.html", token=token, form=ResetPasswordForm())
    

@auth.route('/verify/<token>/<action>', methods=['GET'])
def verify(token, action):
    user = User.query.filter_by(verification_token=token).first()

    if user is None:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('auth.login'))

    if user.is_token_expired():
        flash('Your token has expired. You should receive a new one shortly.', 'error')
        send_verification_email(user, action)
        return redirect(url_for('auth.login'))

    if action == 'email':
        user.is_verified = True
        user.is_active = True
        user.verification_token = None
        db.session.add(user)
        db.session.commit()
        login_user(user)
    else:
        return redirect(url_for('auth.reset_password', token=token, _external=True ))
    
    return render_template('index.html', current_year=current_year)







def get_email_domain(email):
    # leading/trailing spaces
    email = email.strip()
    
    parts = email.split('@')
    if len(parts) != 2:
        raise ValueError("Invalid email format")

    return parts[1]


@auth.route('/signup',  methods=['GET', 'POST'])
def signup():
    MAX_FAILED_ATTEMPTS = current_app.config.get('MAX_FAILED_ATTEMPTS', 5)
    LOCKOUT_TIME_MINUTES = current_app.config.get('LOCKOUT_TIME_MINUTES', 15)
    logging.debug(f"LOCKOUT_TIME_MINUTES: {LOCKOUT_TIME_MINUTES}")
    response = {'redirect': None,
                'code':103,
                'message': '',
                'authenticated': False}

    ip = request.remote_addr
    now = datetime.utcnow()
    # Clean up old entries
    

    signup_request_count[ip] = [timestamp for timestamp in signup_request_count.get(ip, []) if timestamp > now - timedelta(minutes=LOCKOUT_TIME_MINUTES)]
    
    if request.method == "POST":
        if len(signup_request_count[ip]) >= MAX_FAILED_ATTEMPTS:
            return jsonify({'error': 'Too many signup attempts. Please try again later.'}), 429
        signup_request_count[ip].append(now)

        form_data = request.get_json()
        form = SignupForm(data=form_data) 
        password = clean(form_data.get("password"))
        is_valid, message = functions.validate_password(password)
        if not is_valid:
            response['message'] = message
            return jsonify(response)
        if form.validate():
            logging.debug("FIRN VAKUDATED ON SUBMIT")
            if form.disappearing_info.data: 
                logging.warning(f"Honeypot triggered. Possible bot submission: {form_data}")
                response = {'redirect': None, 
                        'message': 'Your submission was not processed. Please try again.',
                        'authenticated': False, 'code':111}
                return jsonify(response)
      
            first_name = clean(form_data.get("first_name"))
            last_name = clean(form_data.get("last_name"))
            email = clean(form_data.get("email").lower().strip())
            company_name = clean(form_data.get("company_name"))
            company_phone = clean(form_data.get("company_phone"))
            fax = clean(form_data.get("fax"))
            street = clean(form_data.get("street_address"))
            city = clean(form_data.get("city"))
            province = clean(form_data.get("province"))
            postal_code = clean(form_data.get("postal"))
            password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            
            user = User.query.filter_by(email=email).first()
            if user:
                if not user.is_verified:
                    response = {'redirect': None, 
                            'message': 'This user already exists and pending verification. Please check your email.',
                            'authenticated': False, 'code': 103}
                    send_verification_email(user, 'email')
                else:
                    response = {'redirect': None, 
                            'message': 'This user already exists. Please try logging in.',
                            'authenticated': False, 'code': 103}
                return jsonify(response) 
            email_domain = get_email_domain(email)
            account = Account.query.filter_by(email_domain=email_domain).first()
            if account:
                user = User(account_id=account.id, first_name=first_name,
                        last_name=last_name, password_hash=password_hash,
                        email=email
                        )
                
                db.session.add(user)
                db.session.commit()
                send_verification_email(user, 'email')

            else:
                account = Account(name=company_name, phone=company_phone,
                                fax=fax, street=street,
                                city=city, province=province,
                                postal_code=postal_code, email_domain=email_domain)
                db.session.add(account)
                db.session.commit()
                user = User(account_id=account.id, first_name=first_name,
                        last_name=last_name, password_hash=password_hash, 
                        email=email, is_admin=True)
                        
                db.session.add(user)
                db.session.commit()
                send_verification_email(user, 'email')

            response['redirect'] = '/login'
            response['message'] = "Success! You've received a verification email."
            response['code'] = 101
            print(f"response: {response}")
            return jsonify(response)
        
        logging.warning(form.errors)
        response['message'] = "Unable to signup at this time. Please try again."
        response['code'] = 103
        print(f"response: {response}")
        return jsonify(response)
    
    else:
        if current_user.is_authenticated:
            return render_template("index.html")
        else:
            return render_template("signup.html", form=SignupForm())


from flask import Flask, render_template, request
from flask_login import UserMixin, login_user, LoginManager, login_required, \
    current_user, logout_user
from urllib.parse import urlparse
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from app.database import db, User, Account
from threading import Thread
from flask_mail import Mail, Message
import re


def send_mail(subject, recipient, body, html):
    """
    Sends an email
    
    :param str subject: Email subject.
    :param str recipient: Email recipient.
    :param str body: Email body as a string
    :param str html: Email body in html
    """
    
    from app import mail
    try:
        msg = Message(subject, recipients=[recipient])
        # msg.body = body
        msg.html = html

        # Async send (optional)
        # Thread(target=send_async_email, args=(app, msg)).start()

        mail.send(msg)
        
    except Exception as e:
        print("Email failed to send: "+ str(e)) 

def authenticate_and_login(email, password):
    """
    Attempts to authenticate the user with the given values.
    If authenticated, the user is loged in and returns True else False.
    
    :param str email: The user's email.
    :param str password: The user's password.

    :return: Returns True if authenticated, False if not
    """
    user = User.query.filter_by(email=email).first()
    if user:
        user_pwhash = user.password_hash
        if check_password_hash(user_pwhash, password):
            login_user(user)
            user.login_successful()
            return True
    user.login_failed()
    return False


def url_has_allowed_host_and_scheme(url, allowed_hosts=None, require_https=False):
    # Get the host and scheme of the URL
    parsed_url = urlparse(url)
    
    if not parsed_url.netloc:
        # If no host is specified, allow it (local redirects)
        return True
    
    # Only allow certain hosts
    if allowed_hosts is not None and parsed_url.netloc not in allowed_hosts:
        return False
    
    # If HTTPS is required, check the scheme
    if require_https and parsed_url.scheme != "https":
        return False
    
    # URL is allowed if it passes all checks
    return True



def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*]', password):
        return False, "Password must contain at least one special character."
    return True, ""
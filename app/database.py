from flask_sqlalchemy import SQLAlchemy
from flask import current_app
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Text, TIMESTAMP, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timedelta
import uuid
import logging


db = SQLAlchemy()

class Account(db.Model):
    __tablename__ = 'accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    phone = db.Column(db.String)
    fax = db.Column(db.String)
    street = db.Column(db.String)
    city = db.Column(db.String)
    province = db.Column(db.String)
    postal_code = db.Column(db.String) 
    email_domain = db.Column(db.String, nullable=False)


class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    phone = db.Column(db.String)
    password_hash = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.TIMESTAMP)
    
    # Email verification fields
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String, unique=True, nullable=True)
    token_created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=True) 

    account = db.relationship("Account")

    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def generate_verification_token(self):
        """Generate a unique token for email verification."""
        self.verification_token = str(uuid.uuid4())
        self.token_created_at = datetime.utcnow()
        db.session.commit()

    def is_token_expired(self):
        """Check if the verification token is expired (e.g., valid for 24 hours)."""
        if self.token_created_at:
            return datetime.utcnow() > self.token_created_at + timedelta(days=1)
        return True

    def is_locked_out(self):
        if self.lockout_until and self.lockout_until > datetime.utcnow():
            return True
        return False
    
    def login_failed(self):
        MAX_FAILED_ATTEMPTS = current_app.config.get('MAX_FAILED_ATTEMPTS', 5)
        LOCKOUT_TIME_MINUTES = current_app.config.get('LOCKOUT_TIME_MINUTES', 15)
        logging.info(f"Failed login attempt for user {self.email} at {datetime.utcnow()}")
        self.failed_attempts += 1
        if self.failed_attempts >= MAX_FAILED_ATTEMPTS:
            self.lockout_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_TIME_MINUTES)
        db.session.commit()

    def login_successful(self):
        self.failed_attempts = 0
        self.lockout_until = None
        db.session.commit()


class Customer(db.Model):
    __tablename__ = 'customers'
    
    id = db.Column(db.Integer, primary_key=True)
    customer_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), unique=True, nullable=False)
    
    account = db.relationship("Account")


class Carrier(db.Model):
    __tablename__ = 'carriers'
    
    id = db.Column(db.Integer, primary_key=True)
    carrier_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), unique=True, nullable=False)
    
    account = db.relationship("Account")


class UserSetting(db.Model):
    __tablename__ = 'user_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    data = db.Column(JSON)

    user = db.relationship("User")
    


class LoadManifest(db.Model):
    __tablename__ = 'load_manifests'
    
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(JSON)
    created_at = db.Column(TIMESTAMP)
    modified_at = db.Column(TIMESTAMP)


class Order(db.Model):
    __tablename__ = 'orders'
    
    id = db.Column(db.Integer, primary_key=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    data = db.Column(JSON)
    created_at = db.Column(TIMESTAMP)
    modified_at = db.Column(TIMESTAMP)
    modified_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    user_created = db.relationship("User", foreign_keys=[generated_by])
    user_modified = db.relationship("User", foreign_keys=[modified_by])
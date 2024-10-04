import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    STRIPE_API_KEY = os.environ.get('STRIPE_API_KEY')
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT'))
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = ("Logisco", "info@shipflow.xyz")
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    ENVIRONMENT = os.environ.get('ENVIRONMENT')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_FAILED_ATTEMPTS = int(os.environ.get('MAX_FAILED_ATTEMPTS'))
    LOCKOUT_TIME_MINUTES = int(os.environ.get('LOCKOUT_TIME_MINUTES'))
    

csp = {
    "default-src": "'self'",
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "script-src": ["'self'"],
    "img-src": "'self'"
}


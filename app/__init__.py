from flask import Flask, render_template, request, session
from flask_mail import Mail
from flask_login import UserMixin, login_user, LoginManager, login_required, \
    current_user, logout_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from app.database import db
import app.config
import logging
import os
from dotenv import load_dotenv
from datetime import datetime
from app.forms import LoginForm
from pathlib import Path
from app.database import User, Account
import app.functions
print(app.config.csp)
load_dotenv()
# load_dotenv(Path('../.env'))
# print(os.environ)


# Logging configs
log_format = '[%(asctime)s] %(levelname)s [line %(lineno)d in %(module)s]: %(message)s'
log_datefmt='%Y-%m-%d %H:%M:%S'
logging.basicConfig(
    format=log_format,
    datefmt=log_datefmt,
    level=logging.ERROR
)
log_level = os.getenv('LOG_LEVEL', 'WARNING').upper()
logging.getLogger().setLevel(getattr(logging, log_level, logging.WARNING))

app = Flask(__name__)

# Initializatons
# Loading configuration from config.Config
app.config.from_object(config.Config)

talisman = Talisman(   
    app,     
    force_https=True,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_max_age=31536000, 
    content_security_policy=config.csp)

# flask login manager
login_manager = LoginManager()
login_manager.init_app(app)

mail = Mail()

# Blueprints registerations
from app.blueprints.auth import auth
app.register_blueprint(auth)
from app.blueprints.billing import billing
app.register_blueprint(billing)

# Initializations
db.init_app(app)
mail.init_app(app)
migrate = Migrate(app, db)

current_year = datetime.now().year


with app.app_context():
    db.create_all()
    print("executed in context")
    


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def before_request():
    ...
    # if not access_allowed():
    #     return jsonify({"message":"Unauthorized access"}), 403

@app.route('/')
def index():
    return render_template('index.html', current_year=current_year)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', current_year=current_year)


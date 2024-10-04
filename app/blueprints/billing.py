from flask import Blueprint
billing = Blueprint('billing', __name__)

@billing.route('/billing')
def billing_page():
    return "Billing Page"
    
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, \
    SelectField, HiddenField, FileField, EmailField, DateField, TimeField
from wtforms.validators import DataRequired, InputRequired, Regexp, Email, Length, EqualTo


# disappearing_info fields are honeypot fields

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], 
                        render_kw={"class": "input1", "placeholder":"Email*"}, )
    password = PasswordField('Password', validators=[DataRequired()], 
                        render_kw={"class": "input1", "placeholder":"Password*"} )
    disappearing_info = HiddenField()
    login = SubmitField('Sign in', render_kw={"class":"btn btn-lg btn-light"})


class SignupForm(FlaskForm):

    first_name = StringField('First Name', validators=[DataRequired(), Length(min=1, max=50)],
    render_kw={"class": "form-control col-sm-4", "placeholder":"First Name*"})
    
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=1, max=50)],
    render_kw={"class": "form-control col-sm-4", "placeholder":"Last Name*"})  

    email = StringField('Your Email', validators=[DataRequired(), Email()], 
    render_kw={"class": "form-control col-sm-4", "placeholder":"Email*"}, )

    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)], 
    render_kw={"class": "form-control col-sm-4", "placeholder":"Password*"} )
    
    company_name = StringField('Company Name', validators=[DataRequired(), Length(min=1, max=80)],
    render_kw={"class": "form-control col-sm-4", "placeholder":"Company / Business Name"})
    
    company_phone = StringField('Phone', validators=[Length(max=20)],
    render_kw={"class": "form-control col-sm-4", "placeholder":"Phone"})

    fax = StringField('Fax', validators=[Length(max=20)],
    render_kw={"class": "form-control col-sm-4", "placeholder":"Fax"})
    
    street_address = StringField('Address', validators=[Length(max=50)],
    render_kw={"class": "form-control col-sm-4", "placeholder":"Address"})
    
    city = StringField('City', validators=[Length(max=50)],
    render_kw={"class": "form-control col-sm-4", "placeholder":"City"})
    
    province = StringField('Province', validators=[Length(max=20)],
    render_kw={"class": "form-control col-sm-4", "placeholder":"Province"})
    
    postal = StringField('Postal Code', validators=[Length(max=7)],
    render_kw={"class": "form-control col-sm-4", "placeholder":"Postal Code"})
    
    disappearing_info = HiddenField()
    signup = SubmitField('Sign up', render_kw={"class":"btn btn-lg btn-light btn-primary"})


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], 
    render_kw={"class": "form-control col-sm-4", "placeholder":"Email*"}, )
    submit = SubmitField('Submit', render_kw={"class":"btn btn-lg btn-light"})


class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', [InputRequired(), EqualTo('confirm_password', message='Passwords must match')],
                                 render_kw={"class": "input1", "placeholder": "New Password"}, 
                                 name="new_password")
    confirm_password = PasswordField('Repeat Password',
                                     render_kw={"class": "input1", "placeholder": "Confirm Password"},
                                     name="confirm_password")
    disappearing_info = HiddenField()
    submit = SubmitField('Reset Password', render_kw={"class": "btn btn-lg btn-light"})
# forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        InputRequired(message='Email is required'),
        Email(message='Invalid email address'),
        Length(max=120)
    ])
    password = PasswordField('Password', validators=[
        InputRequired(message='Password is required'),
        Length(min=6, max=60)
    ])
    submit = SubmitField('Login')


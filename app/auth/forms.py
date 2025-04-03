from flask_wtf import FlaskForm
from wtforms import PasswordField, BooleanField, SubmitField
from wtforms.fields import EmailField
from wtforms.validators import DataRequired, Length, Email


class LoginForm(FlaskForm):
    email = EmailField(
        "Email",
        validators=[
            DataRequired(),
            Length(
                min=4,
                max=128,
                message="Email must be between 4 and 128 characters long",
            ),
            Email(),
        ],
        render_kw={"placeholder": " "},
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(
                min=8,
                max=64,
                message="Password must be between 8 and 64 characters long",
            ),
        ],
        render_kw={"placeholder": " "},
    )
    remember_me = BooleanField(" Keep me logged in")
    
    cancel = SubmitField(label="Cancel", render_kw={"formnovalidate": True})
    submit = SubmitField("Log In")
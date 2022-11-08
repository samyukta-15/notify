from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField

class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")

class SearchForm(FlaskForm):
	searched = StringField("Searched", validators=[DataRequired()])
	submit = SubmitField("Submit")

class PostForm(FlaskForm):
	title = StringField("Title", validators=[DataRequired()])
	content = CKEditorField('Content',  validators=[DataRequired()])
	author = StringField("Author")
	submit = SubmitField("Submit")

class UserForm(FlaskForm):
	name = StringField("Name", validators=[DataRequired()])
	username = StringField("Username", validators=[DataRequired()])
	email = StringField("Email", validators=[DataRequired()])
	password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Password must match')])
	password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
	submit = SubmitField("Submit")

class ResetRequestForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired()])
	submit = SubmitField('Reset Password', validators=[DataRequired()])

class ResetPasswordForm(FlaskForm):
	password = PasswordField('Password', validators=[DataRequired()])
	password2 = PasswordField('Confirm Password', validators=[DataRequired()])
	submit = SubmitField('Submit', validators=[DataRequired()])
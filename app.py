from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_ckeditor import CKEditor
from flask_ckeditor import CKEditorField
from itsdangerous import JSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://xbygbrqeyqbxik:f54595446c44149b5d3f8b2c34ca52a3375b392b0e973a82b2ff75a26c1859df@ec2-35-170-21-76.compute-1.amazonaws.com:5432/dfguougghgv4su'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:BombayTimes@localhost/users'

app.config['SECRET_KEY'] = "no one is supposed to know"

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = "repassflask@gmail.com"
app.config['MAIL_PASSWORD'] = "veyjqmqkugqihsag"

db = SQLAlchemy(app)
migrate = Migrate(app, db)
ckeditor = CKEditor(app)
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))

@app.route('/')
def index():
	return render_template("index.html")

class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password_hash, form.password.data):
				login_user(user)
				flash("Login Successful")
				return redirect(url_for('dashboard'))
			else:
				flash("Wrond Password- Try Again")
		else:
			flash("User doesn't Exist- Try Again")
	return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	flash("You have been logged out!")
	return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
	form = UserForm()
	id = current_user.id
	name_to_update = Users.query.get_or_404(id)
	if request.method == "POST":
		name_to_update.name = request.form['name']
		name_to_update.email = request.form['email']
		name_to_update.username = request.form['username']

		try:
			db.session.commit()
			flash("User Updated Successfully")
			return render_template("dashboard.html", form=form, name_to_update=name_to_update)
		except:
			flash("ERROR")
			return render_template("dashboard.html", form=form, name_to_update=name_to_update)
	
	else:
		return render_template("dashboard.html", form=form, name_to_update=name_to_update, id=id)

	return render_template('dashboard.html')

@app.route('/admin')
@login_required
def admin():
	id = current_user.id
	our_users = Users.query.order_by(Users.date_added)
	if id == 24:
		return render_template("admin.html", our_users=our_users)
	else:
		flash("Sorry you need to be admin to access page")
		return redirect(url_for('dashboard'))

# pass variables to navbar 
@app.context_processor
def base():
	form = SearchForm()
	return dict(form=form)

class SearchForm(FlaskForm):
	searched = StringField("Searched", validators=[DataRequired()])
	submit = SubmitField("Submit")

@app.route('/search', methods=["POST"])
def search():
	form = SearchForm()
	posts = Posts.query
	if form.validate_on_submit():
		post.searched = form.searched.data
		posts = posts.filter(Posts.content.like('%' + post.searched + '%'))
		posts = posts.order_by(Posts.title).all()
		return render_template("search.html", form=form, searched= post.searched, posts=posts)
		# now we can use "searched" on search.html
		# searched = whatever was typed by the user in the search bar

class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(255))
	content = db.Column(db.Text)
	author = db.Column(db.String(255))
	date_posted = db.Column(db.DateTime, default=datetime.utcnow)
	poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class PostForm(FlaskForm):
	title = StringField("Title", validators=[DataRequired()])
	content = CKEditorField('Content',  validators=[DataRequired()])
	author = StringField("Author")
	submit = SubmitField("Submit")

@app.route('/posts')
def posts():
	posts = Posts.query.order_by(Posts.date_posted)
	return render_template("posts.html", posts=posts)

@app.route('/posts/<int:id>')
def post(id):
	post = Posts.query.get_or_404(id)
	return render_template('post.html', post=post)

@app.route('/add-post', methods=['GET', 'POST'])
@login_required
def add_post():
	form = PostForm()

	if form.validate_on_submit():
		poster = current_user.id
		post = Posts(title=form.title.data, content= form.content.data, author= form.author.data, poster_id= poster)
		form.title.data = ''
		form.content.data = ''
		form.author.data = '' 

		db.session.add(post)
		db.session.commit()
		flash("Blog Post Submitted Successfully")

	return render_template("add_post.html", form=form)

@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
	post = Posts.query.get_or_404(id)
	form = PostForm()

	if form.validate_on_submit():
		post.title = form.title.data
		post.author = form.author.data
		post.content =form.content.data

		db.session.add(post)
		db.session.commit()
		flash("Post has been updated!")

		return redirect(url_for('post', id=post.id))

	if current_user.id == post.poster_id or current_user.id == 24:
		form.title.data = post.title
		form.author.data = post.author
		form.content.data = post.content
		return render_template('edit_post.html', form=form, post= post)

	else:
		flash("You aren't authorised to edit the blog post")
		posts = Posts.query.order_by(Posts.date_posted)
		return render_template("posts.html", posts=posts)

# delete post
@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
	post_to_delete = Posts.query.get_or_404(id)
	id = current_user.id
	if id == post_to_delete.poster.id or id == 24:

		try:
			db.session.delete(post_to_delete)
			db.session.commit()

			flash("Blog Post was Deleted!")

			posts = Posts.query.order_by(Posts.date_posted)
			return render_template("posts.html", posts=posts)

		except:
			flash("Error while deleting post!")
			posts = Posts.query.order_by(Posts.date_posted)
			return render_template("posts.html", posts=posts)

	else:
		flash("You aren't authorised to delete post")
		posts = Posts.query.order_by(Posts.date_posted)
		return render_template("posts.html", posts=posts)

class Users(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable= False, unique=True)
	name = db.Column(db.String(200), nullable=False)
	email = db.Column(db.String(120), nullable= False, unique=True)
	date_added = db.Column(db.DateTime, default=datetime.now)
	password_hash = db.Column(db.String(128))
	posts = db.relationship('Posts', backref='poster')

	def get_token(self, expires_sec=300):
		serial = Serializer(app.config['SECRET_KEY'])
		return serial.dumps({'user_id': self.id}).decode('utf-8')

	@staticmethod
	def verify_token(token):
		serial = Serializer(app.config['SECRET_KEY'])
		try:
			user_id = serial.loads(token)['user_id']
		except:
			return None
		return Users.query.get(user_id)

with app.app_context():
	db.create_all()

class UserForm(FlaskForm):
	name = StringField("Name", validators=[DataRequired()])
	username = StringField("Username", validators=[DataRequired()])
	email = StringField("Email", validators=[DataRequired()])
	password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Password must match')])
	password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
	submit = SubmitField("Submit")

@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
	# name variable is being used in html file
	name = None
	form = UserForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(email=form.email.data).first()
		
		if user is None:
			hashed_pw= generate_password_hash(form.password_hash.data, "sha256")
			user = Users(name=form.name.data, username=form.username.data, email=form.email.data, password_hash= hashed_pw)
			db.session.add(user)
			db.session.commit()

		name = form.name.data
		form.name.data=''
		form.username.data=''
		form.email.data= ''
		form.password_hash.data= ''
		flash("User added successfully!")

	our_users = Users.query.order_by(Users.date_added)

	return render_template("add_user.html", form= form, name=name, our_users=our_users)

@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
	form = UserForm()
	id = current_user.id
	name_to_update = Users.query.get_or_404(id)
	if request.method == "POST":
		name_to_update.name = request.form['name']
		name_to_update.email = request.form['email']
		name_to_update.username = request.form['username']

		try:
			db.session.commit()
			flash("User Updated Successfully")
			return render_template("update.html", form=form, name_to_update=name_to_update)
		except:
			flash("ERROR")
			return render_template("update.html", form=form, name_to_update=name_to_update)
	
	else:
		return render_template("update.html", form=form, name_to_update=name_to_update, id=id)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
	if id == current_user.id or current_user.id == 24:
		user_to_delete = Users.query.get_or_404(id)
		name = None
		form = UserForm()

		try:
			db.session.delete(user_to_delete)
			db.session.commit()
			flash("User deleted successfully")

			our_users = Users.query.order_by(Users.date_added)
			return render_template("index.html", form= form, name=name, our_users=our_users)
		except:
			flash("ERROR")
			return render_template("index.html", form= form, name=name, our_users=our_users)
	
	else:
		flash("Sorry you cannot delete the user")
		return redirect(url_for('dashboard'))

@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500

class ResetRequestForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired()])
	submit = SubmitField('Reset Password', validators=[DataRequired()])


class ResetPasswordForm(FlaskForm):
	password = PasswordField('Password', validators=[DataRequired()])
	password2 = PasswordField('Confirm Password', validators=[DataRequired()])
	submit = SubmitField('Submit', validators=[DataRequired()])

def send_mail(user):
	token= user.get_token()
	msg=Message('Password Reset Request', recipients=[user.email], sender='repassflask@gmail.com')
	msg.body= f''' To reset your password. Please follow the link below. 
	{url_for('reset_token', token=token, _external=True)}
	If you didn't send a password reset request. Please ignore the message.
	'''
	mail.send(msg)

@app.route('/reset_password',  methods=['GET', 'POST'])
def reset_request():
	form = ResetRequestForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(email=form.email.data).first()
		if user:
			send_mail(user)
			flash("Reset request sent. Check your mail.")
			return redirect(url_for('login'))

	return render_template('reset_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
	user = Users.verify_token(token)
	if user is None:
		flash('Invalid Token or Expired')
		return redirect(url_for('reset_request'))

	form = ResetPasswordForm()
	if form.validate_on_submit():
		hashed_password= generate_password_hash(form.password.data)
		# hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user.password_hash=hashed_password
		db.session.commit()
		flash('Password changed! Please login')
		return redirect(url_for('login'))
	return render_template('change_password.html', form=form)


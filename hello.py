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

# create a Flask instance
app = Flask(__name__)

ckeditor = CKEditor(app)

# add database
# uri means uniform resource indicator
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:BombayTimes@localhost/users'

# csrf token
app.config['SECRET_KEY'] = "no one is supposed to know"

# initialise database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))

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
		name_to_update.favorite_color = request.form['favorite_color']
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
	if id == 14:
		return render_template("admin.html", our_users=our_users)
	else:
		flash("Sorry you need to be admin to access page")
		return redirect(url_for('dashboard'))

# pass variables to navbar (mainly csrf token)
@app.context_processor
def base():
	form = SearchForm()
	return dict(form=form)

# create a search form
class SearchForm(FlaskForm):
	# because the form's name is searched
	searched = StringField("Searched", validators=[DataRequired()])
	submit = SubmitField("Submit")

# navbar search function
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

# create a blog post table
class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(255))
	content = db.Column(db.Text)
	author = db.Column(db.String(255))
	date_posted = db.Column(db.DateTime, default=datetime.utcnow)
	slug = db.Column(db.String(255))
	poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))

# create a blog post form
class PostForm(FlaskForm):
	title = StringField("Title", validators=[DataRequired()])
	content = CKEditorField('Content',  validators=[DataRequired()])
	author = StringField("Author")
	slug = StringField("Slug", validators=[DataRequired()])
	submit = SubmitField("Submit")

# list of posts
@app.route('/posts')
def posts():
	posts = Posts.query.order_by(Posts.date_posted)
	return render_template("posts.html", posts=posts)

# individual posts
@app.route('/posts/<int:id>')
def post(id):
	post = Posts.query.get_or_404(id)
	return render_template('post.html', post=post)

# add post 
@app.route('/add-post', methods=['GET', 'POST'])
@login_required
def add_post():
	form = PostForm()

	if form.validate_on_submit():
		poster = current_user.id
		post = Posts(title=form.title.data, content= form.content.data, author= form.author.data, poster_id= poster, slug= form.slug.data)
		form.title.data = ''
		form.content.data = ''
		form.author.data = '' 
		form.slug.data = ''

		db.session.add(post)
		db.session.commit()
		flash("Blog Post Submitted Successfully")
	return render_template("add_post.html", form=form)

# edit post
@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
	post = Posts.query.get_or_404(id)
	form = PostForm()

	# old post data
	if form.validate_on_submit():
		post.title = form.title.data
		post.author = form.author.data
		post.slug = form.slug.data
		post.content =form.content.data

		# update database
		db.session.add(post)
		db.session.commit()
		flash("Post has been updated!")

		return redirect(url_for('post', id=post.id))

	if current_user.id == post.poster_id or current_user.id == 14:
		# new post data
		form.title.data = post.title
		form.author.data = post.author
		form.slug.data = post.slug
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
	if id == post_to_delete.poster.id or id == 14:

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



# create users table
class Users(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable= False, unique=True)
	name = db.Column(db.String(200), nullable=False)
	email = db.Column(db.String(120), nullable= False, unique=True)
	favorite_color = db.Column(db.String(120))
	date_added = db.Column(db.DateTime, default=datetime.utcnow)
	password_hash = db.Column(db.String(128))
	posts = db.relationship('Posts', backref='poster')

	@property
	def password(self):
		raise AttributeError('password is not readable attribute')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)	
	

	# create a string
	def __repr__(self):
		return '<Name %r>' % self.name

with app.app_context():
	db.create_all()

class UserForm(FlaskForm):
	name = StringField("Name", validators=[DataRequired()])
	username = StringField("Username", validators=[DataRequired()])
	email = StringField("Email", validators=[DataRequired()])
	favorite_color = StringField("Favorite Color")
	password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Password must match')])
	password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
	submit = SubmitField("Submit")

# add user info
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
	name = None
	form = UserForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(email=form.email.data).first()
		if user is None:
			hashed_pw= generate_password_hash(form.password_hash.data, "sha256")
			user = Users(name=form.name.data, username=form.username.data, email=form.email.data, favorite_color=form.favorite_color.data, password_hash= hashed_pw)
			db.session.add(user)
			db.session.commit()
		name = form.name.data
		form.name.data=''
		form.username.data=''
		form.email.data= ''
		form.favorite_color.data= ''
		form.password_hash.data= ''
		flash("User added successfully!")
	our_users = Users.query.order_by(Users.date_added)

	return render_template("add_user.html", form= form, name=name, our_users=our_users)

# update user info
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
	form = UserForm()
	id = current_user.id
	name_to_update = Users.query.get_or_404(id)
	if request.method == "POST":
		name_to_update.name = request.form['name']
		name_to_update.email = request.form['email']
		name_to_update.favorite_color = request.form['favorite_color']
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

# delete user info
@app.route('/delete/<int:id>')
@login_required
def delete(id):
	if id == current_user.id or current_user.id == 14:
		user_to_delete = Users.query.get_or_404(id)
		name = None
		form = UserForm()
		try:
			db.session.delete(user_to_delete)
			db.session.commit()
			flash("User deleted successfully")

			our_users = Users.query.order_by(Users.date_added)
			return render_template("add_user.html", form= form, name=name, our_users=our_users)
		except:
			flash("ERROR")
			return render_template("add_user.html", form= form, name=name, our_users=our_users)
	else:
		flash("Sorry you cannot delete the user")
		return redirect(url_for('dashboard'))

# create custome error pages
# invalid url
@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404

# internal server error
@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500

# THE END

class PasswordForm(FlaskForm):
	email = StringField("What's Your Email?", validators=[DataRequired()])
	password_hash = PasswordField("What's Your Password?", validators=[DataRequired()])
	submit = SubmitField("Submit")

# create password test page
@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
	email = None
	password = None
	pw_to_check = None
	passed = None
	form = PasswordForm()

	# validate form
	if form.validate_on_submit():

		email = form.email.data
		password = form.password_hash.data

		form.email.data = ''
		form.password_hash.data = ''

		pw_to_check = Users.query.filter_by(email=email).first()

		# check hash password
		passed = check_password_hash(pw_to_check.password_hash, password)

	return render_template("test_pw.html", email=email, password=password, pw_to_check=pw_to_check, passed=passed, form=form)


# create name form 
class NamerForm(FlaskForm):
	name = StringField("What's Your Name?", validators=[DataRequired()])
	submit = SubmitField("Submit")

# create name page
@app.route('/name', methods=['GET', 'POST'])
def name():

	# create 'name' variable to hold data entered by user
	name = None
	form = NamerForm()

	# validate form
	if form.validate_on_submit():

		# assign value entered by user to the 'name' variable
		name = form.name.data 

		# clear 'field data' for the next user
		form.name.data = ''

		# flash message
		flash("Form Submitted Successfully!")

	return render_template("name.html", name=name, form=form)

# create a route decorator
@app.route('/')
def index():
	fname= "John"
	filter_exec= "This is application of <strong> safe </strong> "
	pizza = ["Cheese", "Mushroom", "Chicken", 30]
	return render_template("index.html", fname=fname, filter_exec=filter_exec, pizza=pizza)

@app.route('/user/<name>')
def user(name):
	return render_template("user.html", user_name=name)

# json experiment
@app.route('/date')
def get_current_date():
	return {"Date": date.today()}
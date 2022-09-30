from flask import Flask, render_template


# create a Flask instance
app = Flask(__name__)

# create a route decorator
@app.route('/')

# def index():
# 	return "<h1>Hello World</h1>"

def index():
	fname= "John"
	filter_exec= "This is application of <strong> safe </strong> "
	pizza = ["Cheese", "Mushroom", "Chicken", 30]
	return render_template("index.html", fname=fname, filter_exec=filter_exec, pizza=pizza)

@app.route('/user/<name>')

def user(name):
	return render_template("user.html", user_name=name)

# create custome error pages
@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500
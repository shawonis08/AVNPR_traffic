# from flask import Flask, render_template
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField
#
# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'Thisisasecret!'
#
# class LoginForm(FlaskForm):
#     username = StringField('username')
#     password = PasswordField('password')
#
# @app.route('/form', methods=['GET', 'POST'])
# def form():
#     form = LoginForm()
#
#     if form.validate_on_submit():
#         return '<h1>The username is {}. The password is {}.'.format(form.username.data, form.password.data)
#     return render_template('form.html', form=form)
#
# if __name__ == '__main__':
#     app.run(debug=True)
import os

if not os.path.exists('upload'):
    os.makedirs('upload')

# app.py
from functools import wraps
from flask import Flask, request, Response

app = Flask(__name__)


def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return username == 'admin' and password == 'secret'


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/private")
@requires_auth  # requires_auth decorator for basic auth
def private_page():
    return "Hello I'm Private!!"


if __name__ == "__main__":
    app.run()

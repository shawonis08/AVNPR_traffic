from main import app
from flask import render_template


@app.route('/')
def index():
    return '<h1>test</h1>'


@app.route('/login')
def login():
    return render_template('login.html')

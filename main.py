from flask import Flask, render_template
# from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)


@app.route('/')
def upload_file():
    return render_template('login.html')

# app.config.from_pyfile('config.py')
#
# db = SQLAlchemy(app)
#
# from views import *
if __name__ == '__main__':
    app.run(debug=True)

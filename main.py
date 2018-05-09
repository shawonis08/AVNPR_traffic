from flask import Flask
# pip install flask-sqlalchemy
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config.from_pyfile('config.py')

db = SQLAlchemy(app)

# from models import *
# db.create_all()


from views import *

if __name__ == '__main__':
    app.run(debug=True)

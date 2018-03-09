import os
DEBUG = True
db_path = os.path.join(os.path.dirname(__file__), 'main.db')
SQLALCHEMY_DATABASE_URI = 'sqlite:///{}'.format(db_path)
SECRET_KEY = 'Thisisasecretkey!'

import os
DEBUG = True
db_path = os.path.join(os.path.dirname(__file__), 'main.db')
SQLALCHEMY_DATABASE_URI = 'sqlite:///{}'.format(db_path)
# SQLALCHEMY_DATABASE_URI = 'sqlite:////mnt/C/Users/shawo/Desktop/AVNPR_traffic/main.db'
SECRET_KEY = 'Thisisasecretkey!'

from main import db
from views import *


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)




# class Server(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     statusvalue = db.Column(db.Integer)


# ***for create database follow the instruction
# from main import db
from models import *
# db.create_all()

from main import db


class User(db.model):
    id = db.Coloum(db.Integer, primary_key=True)
    Public_id = db.Coloum(db.String(50), unique=True)
    name = db.Coloum(db.String(50))
    password = db.Coloum(db.String(80))
    admin = db.Coloum(db.Boolean)

from main import app, db
from flask import render_template, request, jsonify
from models import *
import uuid
from werkzeug.security import generate_password_hash, check_password_hash


@app.route('/')
def index():
    return '<h1>test</h1>'


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/user', methods=['GET'])
def get_all_user():
    all_users = User.query.all()
    output = []
    for user in all_users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        output.append(user_data)
    return jsonify({'all_users': output})


@app.route('/user/<user_id>', methods=['GET'])
def get_one_user():
    return ''


@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hash_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hash_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'new user create'})


@app.route('/user/<user_id>', methods=['PUT'])
def promote_user():
    return ''


@app.route('/user/<user_id>', methods=['DELETE'])
def delete_user():
    return ''

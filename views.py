from main import app, db
from flask import render_template, request, jsonify, make_response
from models import *
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from forms import LoginForm


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id = data['public_id']).first()
            print(jsonify({"test":current_user}))
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/')
def index():
    return '<h1>test</h1>'


@app.route('/user', methods=['GET'])
@token_required
def get_all_user(current_user):
    # if not current_user.admin:
    #     return jsonify({'message': 'Cannot perform that function!'})

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


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user,public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'no user found!'})

    user_data = {'public_id': user.public_id, 'name': user.name, 'password': user.password, 'admin': user.admin}

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
# @token_required
def create_user():
    # if not current_user.admin:
    #     return jsonify({'message': 'Cannot perform that function'})

    data = request.get_json()
    hash_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hash_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'new user create'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
    # if not current_user.admin:
    #     return jsonify({'message': 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'no user found!'})
    user.admin = True
    db.session.commit()
    return jsonify({'message': 'user has been promoted'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    # if not current_user.admin:
    #     return jsonify({'message': 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'no user found!'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'user has been deleted'})


@app.route('/token')
def token():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'Authenticate': 'Login required!'})
    # return render_template('login.html')
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('could not verify', 401, {'Authenticate': 'Login required!'})
    if check_password_hash(user.password, auth.password):
        # token = jwt.encode({'public_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])
        token = jwt.encode({'name': user.name,'id':user.id}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('could not verify', 401, {'Authenticate': 'Login required!'})


#not complete this method
@app.route('/form', methods=['GET', 'POST'])
def form():
    form = LoginForm()

    if form.validate_on_submit():
        return '<h1>The username is {}. The password is {}.'.format(form.username.data, form.password.data)
    return render_template('form.html', form=form)

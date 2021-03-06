import os
from werkzeug.utils import secure_filename
from flask import request, jsonify, make_response
import uuid
from functools import wraps
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from main import app, db
from models import *


# from flask_basicauth import BasicAuth


# token required here
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # auth = request.authorization
        # return f(*args, **kwargs)
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = token
            # current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/')
def index():
    return '<h1>test</h1>'


# view all user data
@app.route('/user/all', methods=['GET'])
@token_required
def get_all_user(current_user):
    # start verifyuser admin or not
    verifyuser = User.query.filter_by(key=current_user).first()
    if not verifyuser.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    # End verifyuser admin or not
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


# view specific user by user unique public_id
@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    # start verifyuser admin or not
    verifyuser = User.query.filter_by(key=current_user).first()
    if not verifyuser.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    # End verifyuser admin or not
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'no user found!'})

    user_data = {'public_id': user.public_id, 'name': user.name, 'password': user.password, 'admin': user.admin}

    return jsonify({'user': user_data})


# create user by admin
@app.route('/user/create', methods=['POST'])
@token_required
def create_user(current_user):
    # start verifyuser admin or not
    verifyuser = User.query.filter_by(key=current_user).first()
    if not verifyuser.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    # End verifyuser admin or not

    data = request.get_json()
    hash_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hash_password, admin=False, key=None)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'new user create'})


# promote general user to admin by admin
@app.route('/user/admin/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    # start verifyuser admin or not
    verifyuser = User.query.filter_by(key=current_user).first()
    if not verifyuser.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    # End verifyuser admin or not

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'no user found!'})
    user.admin = True
    db.session.commit()
    return jsonify({'message': 'user has been promoted'})


# delete user by admin
@app.route('/user/delete/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    # start verifyuser admin or not
    verifyuser = User.query.filter_by(key=current_user).first()
    if not verifyuser.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    # End verifyuser admin or not

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'no user found!'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'user has been deleted'})


# generate_token here for specific user
@app.route('/user/token', methods=['GET'])
def gen_token():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'Authenticate': 'Login required!'})
    # return render_template('login.html')
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('could not verify', 401, {'Authenticate': 'Login required!'})
    if check_password_hash(user.password, auth.password):
        # token = jwt.encode({'public_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])
        token = jwt.encode({'name': user.name, 'id': user.id}, app.config['SECRET_KEY'])
        user.key = token.decode('UTF-8')
        db.session.commit()
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('could not verify', 401, {'Authenticate': 'Login required!'})


# through token generate user info
@app.route('/user/token/verify')
@token_required
def token(current_user):
    user = User.query.filter_by(key=current_user).first()

    if not user:
        return jsonify({'message': 'no user found!'})

    user_data = {'public_id': user.public_id, 'name': user.name, 'password': user.password, 'admin': user.admin}

    return jsonify({'user': user_data})

# app login
@app.route('/user/login', methods=['GET'])
@token_required
def login(current_user):
    user = User.query.filter_by(key=current_user).first()

    if not user:
        return jsonify({'message': 'no user found!'})
    user_data = {'id': user.id, 'public_id': user.public_id, 'name': user.name, 'admin': user.admin}

    return jsonify(user_data)


# app logout
@app.route('/user/logout', methods=['GET'])
@token_required
def logout(current_user):
    user = User.query.filter_by(key=current_user).first()

    if not user:
        return jsonify({'message': 'no user found!'})

    user.key = None
    db.session.commit()

    return jsonify({'message': 'logout successfully'})


# not complete this method
# @app.route('/form', methods=['GET', 'POST'])
# def form():
#     form = LoginForm()
#
#     if form.validate_on_submit():
#         return '<h1>The username is {}. The password is {}.'.format(form.username.data, form.password.data)
#     return render_template('login.html', form=form)


# file upload(key=file)
@app.route('/user/upload', methods=['GET', 'POST'])
@token_required
def upload(current_user):
    user = User.query.filter_by(key=current_user).first()
    if not user:
        return jsonify({'message': 'no user found!'})

    if not os.path.exists('UPLOAD_FOLDER'):
        os.makedirs('UPLOAD_FOLDER')

    if request.method == 'POST':
        uploadfile = request.files['file']
        uploadfile.save(os.path.join('UPLOAD_FOLDER', secure_filename(uploadfile.filename)))

    return jsonify({'message': 'upload completed!'})


# file upload through byte io
@app.route('/user/up', methods=['POST'])
def up():
    if request.method == 'POST':
        return 'ok'
    return jsonify({'message': 'test with byete'})

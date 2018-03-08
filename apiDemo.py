from flask import Flask, jsonify
from flask_restful import Resource, Api
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
api = Api(app, prefix="/api/v1")
auth = HTTPBasicAuth()

Users = [{
    'user_name': 'deep',
    'user_password': 12345
}, {
    'user_name': 'nvd',
    'user_password': 55600
}]


@auth.verify_password
def get_pw(user, passw):
    for u in Users:
        if user in u['user_name']:
            if str(u['user_password']) == passw:
                return True
    return False





class login(Resource):
    @auth.login_required
    def get(self):
        return jsonify(Users)


api.add_resource(login, '/login')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

from flask import Flask,make_response, request, jsonify
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required
from flask_login import LoginManager
from routes import initialize_routes
from d_b import initialize_db
from blockchain import initialize_blockchain
from api_constants import mongo_password
from models import Voter,User
import urllib
import os


os.environ['ENV_FILE_LOCATION'] = './.env'
# print(os.environ.keys())
    
app = Flask(__name__)
app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
app.config.from_envvar('ENV_FILE_LOCATION')

class CustomLoginManager(LoginManager):
    def reload_user(self):
        if request.headers.has_key('Authorization'):
            ctx = _request_ctx_stack.top
            ctx.user = User.get(token=request.headers['Authorization'])
            return
        super(CustomLoginManager,self).reload_user()

login_manager = CustomLoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

# @login_manager.header_loader
# def load_user_from_header(header_val):
#     header_val = header_val.replace('Bearer ', '', 1)
#     try:
#         header_val = base64.b64decode(header_val)
#     except TypeError:
#         pass
#     return User.query.filter_by(api_key=header_val).first()

@login_manager.user_loader
def load_user(user_id):
    return User.objects.get(id=user_id)

api = Api(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

database_name = "Electoral_Rolls"
password = urllib.parse.quote_plus(mongo_password)
DB_URI = "mongodb+srv://HardeepKaur:{}@pythoncluster.6nvxg.mongodb.net/{}?retryWrites=true&w=majority".format(password,database_name)
app.config["MONGODB_HOST"] = DB_URI

initialize_db(app)
initialize_routes(api)
initialize_blockchain()


if __name__ == '__main__':
    app.run()



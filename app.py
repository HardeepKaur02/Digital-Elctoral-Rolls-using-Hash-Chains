from flask import Flask,make_response, request, jsonify
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required
from routes import initialize_routes
from d_b import initialize_db
from blockchain import initialize_blockchain
from api_constants import mongo_password
from models import Voter
import urllib
import os


os.environ['ENV_FILE_LOCATION'] = './.env'
# print(os.environ.keys())
    
app = Flask(__name__)
app.config.from_envvar('ENV_FILE_LOCATION')

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



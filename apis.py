from flask import Flask,make_response, request, jsonify
from flask_restful import Resource
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models import Voter, User
from blockchain import Transaction, add_transaction
import datetime
import time

'''

# SIGNUP
POST /api/auth/signup        -> signs up a user and adds in db

# LOGIN
POST /api/auth/login         -> logs in a user and generates a bearer token for authorisation 

# AUTHENTICATION NEEDED
GET /api/voters/voter_id     -> returns details of the voter with given id, if exists (response code 200) else (response code 401)

# AUTHENTICATION + AUTHORISATION NEEDED
GET /api/voters              -> returns details of all the voters ??? or in a particular constituency ??? valid ???
POST /api/voters             -> insert voter in db
PUT /api/voters/voter_id     -> update voter data having given voter id
DELETE /api/voters/voter_id  -> delete voter from db
POST /api/db_populate -> adds voters to db in bulk and returns 201 success code with empty response body

'''


class api_db(Resource):
    @jwt_required()
    def post(self): ### insert voters in bulk
        voter1_obj = Voter(
            EPIC_ID = "ABC3456789",
            name = "Voter3",
            age = 49,
            gender = "Female",
            address = "Delhi",
            father_name = "Father3"
        )
        voter1_obj.save()

        voter2_obj = Voter(
            EPIC_ID = "ABC4567890",
            name = "Voter4",
            age = 18,
            gender = "Male",
            address = "Kota, Rajasthan",
            father_name = "Father4"
        )
        voter2_obj.save()
        user_id = get_jwt_identity()
        user = User.objects.get(id=user_id)
        transaction_data = {"action": "INSERT ","voter_data": {voter1_obj.to_json(),voter2_obj.to_json()}, "timestamp": datetime.datetime.now().strftime("%c")}
        transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
        add_transaction(transaction)

        return make_response("",201)


class api_voters(Resource):
    @jwt_required()
    def get(self):
        voters = []
        for voter in Voter.objects():
            voters.append(voter.to_json())
        return make_response(jsonify(voters),200)

    @jwt_required()
    def post(self):  ### insert single voter
        content = request.json
        voter_obj = Voter(EPIC_ID = content['EPIC_ID'],name = content['name'],age = content['age'],gender = content['gender'],address = content['address'],father_name = content['father_name'])
        voter_obj.save()
        user_id = get_jwt_identity()
        user = User.objects.get(id=user_id)
        transaction_data = {"action": "INSERT","voter_data": voter_obj.to_json(), "timestamp": datetime.datetime.now().strftime("%c")}
        transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
        add_transaction(transaction)
        
        return make_response("",201)



class api_voter(Resource):
    @jwt_required()
    def get(self,voter_id):
        voter_obj = Voter.objects(EPIC_ID = voter_id).first()
        # user_id = get_jwt_identity()
        # user = User.objects.get(id=user_id)
        # transaction_data = {"action": "SEARCH","voter_data": voter_obj.to_json(), "timestamp": datetime.datetime.now().strftime("%c")}
        # transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
        # print(transaction.to_json())
        # add_transaction(transaction)
        
        if voter_obj:
            return make_response(jsonify(voter_obj.to_json()),200)
        else:
            return make_response("",404)

    @jwt_required()
    def put(self,voter_id):
        content = request.json ## data to be updated
        voter_obj = Voter.objects(EPIC_ID = voter_id).first()
        voter_obj.update(name = content['name'],age = content['age'],gender = content['gender'],address = content['address'],father_name = content['father_name'])
        user_id = get_jwt_identity()
        user = User.objects.get(id=user_id)
        transaction_data = {"action": "UPDATE","voter_data": voter_obj.to_json(), "timestamp": datetime.datetime.now().strftime("%c")}
        transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
        add_transaction(transaction)
        return make_response("",204)

    @jwt_required()
    def delete(self,voter_id):
        voter_obj = Voter.objects(EPIC_ID = voter_id).first()
        user_id = get_jwt_identity()
        user = User.objects.get(id=user_id)
        transaction_data = {"action": "DELETE","voter_data": voter_obj.to_json(), "timestamp": datetime.datetime.now().strftime("%c")}
        transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
        add_transaction(transaction)
        voter_obj.delete()
        return make_response("",204)


class api_signup(Resource):
    def post(self):
        content = request.json
        user = User(email = content['email'], password = content['password'])
        user.hash_password()
        user.save()
        return make_response("",200)

class api_login(Resource):
    def post(self):
        content = request.json
        user = User.objects(email = content['email']).first()
        authorized = user.check_password(content['password'])
        if not authorized:
            return make_response(jsonify({'error': 'Email or password invalid'}),401)
        expires =  datetime.timedelta(minutes=30)
        access_token = create_access_token(identity = str(user.id),expires_delta = expires)
        return make_response(jsonify({"token": access_token}),200)


    


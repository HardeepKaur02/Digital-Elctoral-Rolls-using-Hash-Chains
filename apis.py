from flask import Flask,make_response, request, jsonify, render_template, flash, redirect, url_for
from flask_restful import Resource
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_login import login_user, login_required, logout_user, current_user
from models import Authorised_Officer, Metadata, Voter, User
from blockchain import Transaction, add_transaction
from merkle import MerkleTree, data_verification, verify_consistency
import datetime
import time
import json
from d_b import db

merkle_tree = None

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
valid_actions = ["SEARCH","INSERT","UPDATE","DELETE"]
query_level = {"SEARCH":1, "INSERT":2, "UPDATE":2, "DELETE":2, "SEARCH_2": 2, "GET_ALL":2}

#### JUST FOR CONVENIENCE WHILE TESTING ####
class api_db(Resource):
    @login_required
    def get(self): ### insert voters in bulk
        
        id = 1230001
        voters = []
        for i in range(10):
            id1 = "PAL" + str(id)
            id+=1
            id2 = "RUL" + str(id)
            id+=1  
            voter1_obj = Voter(
                EPIC_ID = id1,
                name = "Voter",
                age = 49,
                gender = "Female",
                address = "Delhi",
                father_name = "Father1",
                part_number = 2,
                part_name = "test",
                assembly_constituency = "Khanna",
                parliamentary_constituency = "Fatehgarh Sahib"
            )

            voter2_obj = Voter(
                EPIC_ID = id2,
                name = "Voter",
                age = 18,
                gender = "Male",
                address = "Kota, Rajasthan",
                father_name = "Father4",
                part_number = 2,
                part_name = "test",
                assembly_constituency = "Payal",
                parliamentary_constituency = "Fatehgarh Sahib"
            )
            user = current_user
            headers = {'Content-Type': 'text/html'}
            #### ACCESSS CHECK - Authorised Officer ####
            if user.level >= query_level['INSERT']:
                auth_officer = user.level_2_id
                #### ACCESS CHECK - Authorised for action in concerned Constituency ####
                if voter1_obj.assembly_constituency in auth_officer.assembly_constituencies:
                    metadata = Metadata(writer=user['email'],timestamp=datetime.datetime.now().strftime("%c"),proof = {})
                    metadata.save()
                    voter1_obj.metadata = metadata
                    voter1_obj.hash = voter1_obj.compute_hash()
                    voter1_obj.save()
                    voters.append(voter1_obj)
                if voter2_obj.assembly_constituency in auth_officer.assembly_constituencies:
                    metadata = Metadata(writer=user['email'],timestamp=datetime.datetime.now().strftime("%c"),proof = {})
                    metadata.save()
                    voter2_obj.metadata = metadata
                    voter2_obj.hash = voter2_obj.compute_hash()
                    voter2_obj.save()
                    voters.append(voter2_obj)

        transaction_data = {"action": "DB_POPULATE ","voter_data": [voter1_obj.to_json(),voter2_obj.to_json()], "timestamp": datetime.datetime.now().strftime("%c")}
        transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
        add_transaction(transaction)
        voters = list(map(lambda x: repr(x),voters))
        global merkle_tree
        merkle_tree = MerkleTree([voters[0],])
        for i in range(len(voters)-1):
            merkle_tree.extend_tree([voters[i+1],])
        print(merkle_tree.root.hash)
        return make_response("",201)

class api_home(Resource):
    @login_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('home.html',user=current_user),200,headers)

class api_search(Resource):
    @login_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('search.html',user=current_user),200,headers)

class api_insert(Resource):
    @login_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('insert.html',user=current_user),200,headers)

class api_update(Resource):
    @login_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('update.html',user=current_user),200,headers)

class api_delete(Resource):
    @login_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('delete.html',user=current_user),200,headers)

class api_merkle_tree(Resource):
    @login_required
    def get(self):
        global merkle_tree
        print(merkle_tree.history)
        return make_response(merkle_tree.root.hash,200)

class api_query_membership(Resource):
    @login_required
    def get(self,voter_id):
        global merkle_tree
        voter_dic = {"EPIC_ID":voter_id}
        voter_str = json.dumps(voter_dic)
        res = data_verification(merkle_tree,voter_str)
        if res:
            print("Waheguru")
            return make_response("Voter data found",200)
        else:
            print("Waheguru Ji")
            return make_response("Voter data not found",400)

class api_query_consistency(Resource):
    @login_required
    def get(self,num_voters):
        global merkle_tree
        print(Voter.objects().order_by('metadata'))
        print("Waheguru")
        all_voters = Voter.objects().order_by('metadata.timestamp')
        print(all_voters)
        print(type(all_voters[0]))
        print("Waheguru waheguru")
        voters = []
        for i in range(int(num_voters)):
            voters.append(repr(all_voters[i]))
        res = verify_consistency(merkle_tree,voters)
        if res:
            print("Waheguru")
            return make_response("Database is consistent",200)
        else:
            print("Waheguru Ji")
            return make_response("Database is not consistent",400)

class api_voters(Resource):
    @login_required
    def get(self):
        headers = request.headers
        user = current_user
        #### ACCESSS CHECK - Authorised Officer ####
        if user.level >= query_level['GET_ALL']:
            auth_officer = user.level_2_id
            voters = []
            #### ACCESS CONTROL - Authorised for action in concerned Constituency ####
            for assembly_constituency in auth_officer.assembly_constituencies:
                for voter in Voter.objects(assembly_constituency = assembly_constituency, block_status = 1):
                    # while voter.block_status == 0:
                    #     voter = voter.forward_ptr
                    # if voter.block_status == 1:
                    voters.append(voter.to_json())
            return make_response(jsonify(voters),200)
        return make_response("Unauthorised Action!",401)

    # @login_required
    # def get(self):
    #     headers = {'Content-Type': 'text/html'}
    #     return make_response(render_template('insert.html',user=current_user),200,headers)

    @login_required
    def post(self):  ### insert a single voter
        content = request.json

        voter_obj = Voter(**content)
        user = current_user
        headers = {'Content-Type': 'text/html'}
        #### ACCESSS CHECK - Authorised Officer ####
        if user.level >= query_level['INSERT']:
            auth_officer = user.level_2_id
            #### ACCESS CHECK - Authorised for action in concerned Constituency ####
            if voter_obj.assembly_constituency in auth_officer.assembly_constituencies:
                already_present = Voter.objects(EPIC_ID = voter_obj.EPIC_ID, block_status=1).first()

                if already_present:
                    flash('Voter id already registered',category = 'error')
                    return make_response(render_template('insert.html',user=current_user),401,headers)

                metadata = Metadata(writer=user['email'],timestamp=datetime.datetime.now().strftime("%c"),proof = {})
                metadata.save()
                voter_obj.metadata = metadata
                voter_obj.hash = voter_obj.compute_hash()
                voter_obj.save()
                global merkle_tree
                merkle_tree.extend_tree([repr(voter_obj)])
                transaction_data = {"action": "INSERT","voter_data": voter_obj.to_json(), "timestamp": datetime.datetime.now().strftime("%c")}
                transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
                add_transaction(transaction)
                flash('Voter inserted successfully',category = 'success')
                data = {"email":user.email, "registered_voter": user.registered_voter, "level": user.level,"actions":[]}                
                return make_response(render_template('home.html',user=current_user,data=data),200,headers)
        flash('Unauthorised Action!',category = 'error')
        return make_response(render_template('insert.html',user=current_user),401,headers)


class api_voter(Resource):
    @login_required
    def get(self,voter_id):
        # voter_obj = Voter.find({"EPIC_ID" : voter_id,"block_status":1})
        voter_obj = Voter.objects(EPIC_ID = voter_id, block_status=1).first()
        if voter_obj:
            user = current_user
            action = "SEARCH_2"
            #### ACCESSS CHECK - Authorised Officer ####
            if user.level >= query_level[action]:
                auth_officer = user.level_2_id
                #### ACCESS CHECK - Authorised for action in concerned Constituency ####
                if voter_obj.assembly_constituency in auth_officer.assembly_constituencies:
                    return make_response(jsonify(voter_obj.to_json_complete()),200)            
            return make_response(jsonify(voter_obj.to_json()),200)                
        return make_response("Voter data not found",404)

    @login_required
    def put(self,voter_id):
        content = request.json ## data to be updated
        voter_obj = Voter.objects(EPIC_ID = voter_id, block_status=1).first()
        if not voter_obj:
            flash('Voter doesn\'t exist',category='error')
            return make_response("Voter doesn't exist",204)
        user = current_user
        #### ACCESSS CHECK - Authorised Officer ####
        if user.level >= query_level['UPDATE']:
            auth_officer = user.level_2_id
            #### ACCESS CHECK - Authorised for action in concerned Constituency ####
            if voter_obj.assembly_constituency in auth_officer.assembly_constituencies:
                prev_content = voter_obj.to_json_complete()
                for key in content:
                    prev_content[key] = content[key]
                new_voter_obj = Voter(**prev_content)
                metadata = Metadata(writer=user['email'],timestamp=datetime.datetime.now().strftime("%c"),proof = {})
                metadata.save()
                new_voter_obj.metadata = metadata
                new_voter_obj.backward_ptr = voter_obj
                new_voter_obj.prev_hash = new_voter_obj.compute_prev_hash()   ### different from voter_obj.hash
                new_voter_obj.hash = new_voter_obj.compute_hash()
                if voter_obj.hash == new_voter_obj.hash:
                    return make_response("No update required",231)
                new_voter_obj.save()
                global merkle_tree
                merkle_tree.extend_tree([repr(new_voter_obj)])
                update_meta = {"block_status":0}
                voter_obj.update(**update_meta)

                transaction_data = {"action": "UPDATE","voter_data": new_voter_obj.to_json(), "timestamp": datetime.datetime.now().strftime("%c")}
                transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
                add_transaction(transaction)
                return make_response("Success",200)
        return make_response("Unauthorised Action!",401)


    @login_required
    def delete(self,voter_id):
        voter_obj = Voter.objects(EPIC_ID = voter_id, block_status=1).first()
        if not voter_obj:
            flash('Voter doesn\'t exist',category='error')
            return make_response("Voter doesn't exist",204)
        user = current_user
        #### ACCESSS CHECK - Authorised Officer ####
        if user.level >= query_level['DELETE']:
            auth_officer = user.level_2_id
            #### ACCESS CHECK - Authorised for action in concerned Constituency ####
            if voter_obj.assembly_constituency in auth_officer.assembly_constituencies:
                prev_content = voter_obj.to_json_complete()
                new_voter_obj = Voter(**prev_content)
                metadata = Metadata(writer=user['email'],timestamp=datetime.datetime.now().strftime("%c"),proof = {})
                metadata.save()
                new_voter_obj.metadata = metadata
                new_voter_obj.backward_ptr = voter_obj
                new_voter_obj.prev_hash = new_voter_obj.compute_prev_hash()   ### different from voter_obj.hash
                new_voter_obj.hash = new_voter_obj.compute_hash()
                new_voter_obj.block_status = 2
                new_voter_obj.save()
                global merkle_tree
                merkle_tree.extend_tree([repr(new_voter_obj)])

                update_meta = {"block_status":0}
                voter_obj.update(**update_meta)
                
                transaction_data = {"action": "DELETE","voter_data": new_voter_obj.to_json(), "timestamp": datetime.datetime.now().strftime("%c")}
                transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
                add_transaction(transaction)
            
                return make_response("Success",200)
        return make_response("Unauthorised Action!",401)


class api_signup(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('signup.html',user=current_user),200,headers)

    def post(self):
        first_entry = request.form.get('firstName')
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')  
        is_voter = request.form.get('voter')
         
        headers = {'Content-Type': 'text/html'}
        user = User.objects(email = email).first()
        if user:
            flash('Email id already registered.', category='error')
        elif not is_voter and len(first_entry) < 2:
            flash('Name must be greater than 1 character.', category='error')
        elif is_voter and len(first_entry) < 10:
            flash('EPIC ID must contain 10 characters.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        elif is_voter:
            voter = Voter.objects(EPIC_ID = first_entry).first()
            if voter:
                user = User(email = email, password = password1,registered_voter=1,voter=voter)
                user.hash_password()
                user.save()
                flash('User created successfully!', category='success')
                return make_response(render_template('login.html',user=current_user),204,headers)
            else:
                flash('EPIC ID is invalid', category = 'error')
                return make_response(render_template('signup.html',user=current_user),400,headers)
        else:
            user = User(email = email, password = password1)
            user.hash_password()
            user.save()
            flash('User created successfully!', category='success')
            return make_response(render_template('login.html',user=current_user),204,headers)
        return make_response(render_template('signup.html',user=current_user),400,headers)


class api_login(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('login.html',user=current_user),200,headers)
        
    def post(self):

        email = request.form.get('email')
        password = request.form.get('password')
        user = User.objects(email = email).first()
        headers = {'Content-Type': 'text/html'}
        if user:
            authorized = user.check_password(password)
            if not authorized:
                flash('Incorrect password, try again.', category='error')
                return make_response(render_template('login.html',user=current_user),401,headers)
            flash('Logged in successfully!', category='success')
            expires =  datetime.timedelta(minutes=30)
            access_token = create_access_token(identity = str(user.id),expires_delta = expires)
            header_val = "Bearer "+ access_token
            headers['Authorization']= header_val
            login_user(user, remember=True)
            actions = []
            for action in valid_actions:
                if query_level[action]<=user.level:
                    actions.append(action)
            print(*actions)
            data = {"email":user.email, "registered_voter": user.registered_voter, "level": user.level,"actions":actions,"token":header_val}
            # return make_response(redirect(url_for('api_home')),301,headers)
            return make_response(render_template('home.html',user=current_user,data=data),200,headers)

        else:
            flash('User doesn\'t exist.', category='error')
            return make_response(render_template('login.html',user=current_user),404,headers)
        
class api_auth_officer(Resource):
    #### HIGHER LEVEL AUTHORISATION REQUIRED ####
    def post(self):
        content = request.json
        auth_off = Authorised_Officer(**content)
        auth_off.save()
        user = User.objects(email = content['email']).first()
        if user:
            user.update(level = 2, level_2_id = auth_off)
        # else:
        #     add user
        return make_response("",204)

    def put(self):
        content = request.json ## data to be updated
        auth_off = Authorised_Officer.objects(auth_id = content['auth_id']).first()
        auth_off.update(**content)
        # user_id = get_jwt_identity()
        # user = User.objects.get(id=user_id)
        # transaction_data = {"action": "UPDATE AUTHORISED OFFICER DATA","data": auth_off.to_json(), "timestamp": datetime.datetime.now().strftime("%c")}
        # transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
        # add_transaction(transaction)
        return make_response("",204)


        
    


from hashlib import new
from flask import Flask,make_response, request, jsonify, render_template, flash, redirect, url_for
from flask_restful import Resource
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_login import login_user, login_required, logout_user, current_user
from models import Authorised_Officer, Metadata, Voter, User
from blockchain import Transaction, add_transaction
from merkle import MerkleTree, data_verification, verify_consistency,rep
import datetime
import time
import json
from d_b import db
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import os

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
valid_actions = ["SEARCH","INSERT","UPDATE","DELETE","QUERY_DATABASE","QUERY_CONSISTENCY","SHOW_DB"]
query_level = {"SEARCH":1, "INSERT":2, "UPDATE":2, "DELETE":2, "SEARCH_2": 2, "GET_ALL":2,"QUERY_DATABASE":1,"QUERY_CONSISTENCY":2,"SHOW_DB":2}

#### JUST FOR CONVENIENCE WHILE TESTING ####
class api_db(Resource):
    # @login_required
    def get(self): ### insert voters in bulk
        
        id = 1230001
        voters = []
        for i in range(10):
            id1 = "RAL" + str(id)
            id2 = "GUL" + str(id)
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
                parliamentary_constituency = "Fatehgarh Sahib",
                signature = bytes("", 'utf-8')
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
                parliamentary_constituency = "Fatehgarh Sahib",
                signature = bytes("", 'utf-8')
            )
            metadata = Metadata(timestamp=datetime.datetime.now().strftime("%c"),proof = {})
            metadata.save()
            voter1_obj.metadata = metadata
            voter1_obj.hash = voter1_obj.compute_hash()
            voter1_obj.save()
            voters.append(voter1_obj)
            voter2_obj.metadata = metadata
            voter2_obj.hash = voter2_obj.compute_hash()
            voter2_obj.save()
            voters.append(voter2_obj)

        try:
            global merkle_tree
            voters_repr = list(map(lambda x: repr(x),voters))    
            merkle_tree = MerkleTree([voters_repr[0],])
            merkle_tree.obj_history.append(voters[0])
            merkle_tree.obj_status.append(1)
            for i in range(len(voters_repr)-2):
                merkle_tree.extend_tree([voters_repr[i+1],])
                merkle_tree.obj_history.append(voters[i+1])
                merkle_tree.obj_status.append(1)
            merkle_tree.extend_tree([voters_repr[-1],])
            merkle_tree.obj_history.append(voters[-1])
            merkle_tree.obj_status.append(1)
            print(merkle_tree.root.hash)
            flash("Session started successfully!",category="success")
            return make_response("",201)
        except:
            flash("Couldn't start a session.", category='error')
            return make_response("",400)

class api_show_db(Resource):
    def get(self):
        voter_chains=[]
        
        for voter in Voter.objects(block_status = 1):
            voter_chain = []
            while voter.prev_hash != '0':
                temp = voter.to_json2()
                voter_chain.append(temp)
                voter = voter.backward_ptr
            temp = voter.to_json2()
            voter_chain.append(temp)
            voter_chains.append(voter_chain)
            
        res = jsonify(voter_chains)
        return make_response(res,"200")

# class api_home(Resource):
#     @login_required
#     def get(self):
#         headers = {'Content-Type': 'text/html'}
#         return make_response(render_template('home.html',user=current_user),200,headers)

class api_index(Resource):
    @login_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('index.html'),200,headers)


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
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('consistent.html',user=current_user),200,headers)

class api_query_membership(Resource):
    @login_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('member.html',user=current_user),200,headers)
     
    def post(self):
        content = request.json
        print(content)
        code_str = ['0','0','0','0','0','0','0','0']
        if content['name'] != "":
            code_str[0] = '1'
        if content['father_name'] != "":
            code_str[1] = '1'
        if content['age'] != "":
            code_str[2] = '1'
        if content['gender'] != "":
            code_str[3] = '1'
        if content['part_number'] != "":
            code_str[4] = '1'
        if content['part_name'] != "":
            code_str[5] = '1'
        if content['assembly_constituency'] != "":
            code_str[6] = '1'
        if content['parliamentary_constituency'] != "":
            code_str[7] = '1'
        global merkle_tree
        # new_leaves = list(map(lambda x: rep(x,code_str),merkle_tree.obj_history))
        new_leaves = []
        for i in range(len(merkle_tree.obj_history)):
            new_leaves.append(rep(merkle_tree.obj_history[i],code_str,active=merkle_tree.obj_status[i]))
        print(new_leaves)
        new_merkle = MerkleTree([new_leaves[0],])
        for i in range(len(new_leaves)-2):
            new_merkle.extend_tree([new_leaves[i+1],])  
        new_merkle.extend_tree([new_leaves[-1],],to_print=1)              
        query = rep(content,code_str,1)
        res,audit_trail = data_verification(new_merkle,query)
        print(query)
        print(audit_trail)
        if res:
            audit_trail = list(map(lambda x: x[0],audit_trail))
            return make_response(jsonify(audit_trail),200)
        return make_response(audit_trail,400)
        

class api_query_consistency(Resource):
    @login_required
    def get(self,num_voters):
        num_voters = int(num_voters)
        global merkle_tree
        all_voters = Voter.objects().order_by('metadata.timestamp')
        greater = False
        if len(all_voters) < num_voters:
            greater = True
            num_voters = len(all_voters)
        voters = []
        for i in range(num_voters):
            voters.append(repr(all_voters[i]))
        res = verify_consistency(merkle_tree,voters)
        if res and greater:
            return make_response("No. of leaves exceeded",204)
        elif res:
            return make_response("Database is consistent",200)
        else:
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

                name_AO = auth_officer.name
                path_name =  "~/Desktop/keys/"+name_AO+".txt"
                f = open (os.path.expanduser(path_name))
                private_key = f.read().encode("utf-8")
                priv_key = RSA.importKey(private_key)
                signer = PKCS1_v1_5.new(priv_key)
                data = voter_obj.to_json_complete()
                data = json.dumps(data)
                h = SHA256.new(data.encode("utf8"))
                signature = signer.sign(h)
                voter_obj.signature = signature

                metadata = Metadata(writer=user['email'],timestamp=datetime.datetime.now().strftime("%c"),proof = {})
                metadata.save()
                voter_obj.metadata = metadata
                voter_obj.hash = voter_obj.compute_hash()
                voter_obj.save()
                global merkle_tree
                merkle_tree.extend_tree([repr(voter_obj)])
                merkle_tree.obj_history.append(voter_obj)
                merkle_tree.obj_status.append(1)
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
            print(voter_obj.metadata.writer)
            ao_user = Authorised_Officer.objects(email = voter_obj.metadata.writer).first()
            pub_key = ao_user.public_key.encode('utf-8')
            pub_key = RSA.importKey(pub_key)
            verifier = PKCS1_v1_5.new(pub_key)

            #### ACCESSS CHECK - Authorised Officer ####
            if user.level >= query_level[action]:
                auth_officer = user.level_2_id
                #### ACCESS CHECK - Authorised for action in concerned Constituency ####
                if voter_obj.assembly_constituency in auth_officer.assembly_constituencies:
                    search_result = voter_obj.to_json_complete()
                    search_result = json.dumps(search_result)
                    h = SHA256.new(search_result.encode("utf8"))
                    signature = voter_obj.signature
                    # print(signature)
                    verified = verifier.verify(h,signature)
                    if verified:
                        print("Signature verified")
                        ### this search returns entire data, though all of it is not displayed on interface
                        return make_response(voter_obj.to_json_complete(),200)         

            search_result = voter_obj.to_json_complete()
            search_result = json.dumps(search_result)
            h = SHA256.new(search_result.encode("utf8"))
            # print(search_result)
            signature = voter_obj.signature
            verified = verifier.verify(h,signature)
            if verified:
                print("Signature verified")
                return make_response(jsonify(voter_obj.to_json()),200)    
            else:
                print("Signature not verified")  
                return make_response("Couldn't verify signature",400)          
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

                name_AO = auth_officer.name
                path_name =  "~/Desktop/keys/"+name_AO+".txt"
                f = open (os.path.expanduser(path_name))
                private_key = f.read().encode("utf-8")
                priv_key = RSA.importKey(private_key)
                signer = PKCS1_v1_5.new(priv_key)
                data = new_voter_obj.to_json_complete()
                data = json.dumps(data)
                h = SHA256.new(data.encode("utf8"))
                signature = signer.sign(h)
                new_voter_obj.signature = signature

                metadata = Metadata(writer=user,timestamp=datetime.datetime.now().strftime("%c"),proof = {})
                print(type(user))
                print(user)
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
                merkle_tree.obj_history.append(new_voter_obj)
                merkle_tree.obj_status.append(1)
                update_meta = {"block_status":0}
                voter_obj.update(**update_meta)
                j = merkle_tree.obj_history.index(voter_obj)
                merkle_tree.obj_status[j]=0
                transaction_data = {"action": "UPDATE","voter_data": new_voter_obj.to_json(), "timestamp": datetime.datetime.now().strftime("%c")}
                transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
                add_transaction(transaction)
                flash("Data updated successfully",category='success')
                return make_response("Success",200)
        flash("Updation failed",category='error')
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

                name_AO = auth_officer.name
                path_name =  "~/Desktop/keys/"+name_AO+".txt"
                f = open (os.path.expanduser(path_name))
                private_key = f.read().encode("utf-8")
                priv_key = RSA.importKey(private_key)
                signer = PKCS1_v1_5.new(priv_key)
                data = new_voter_obj.to_json_complete()
                data = json.dumps(data)
                h = SHA256.new(data.encode("utf8"))
                signature = signer.sign(h)
                new_voter_obj.signature = signature

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
                merkle_tree.obj_history.append(new_voter_obj)
                merkle_tree.obj_status.append(1)

                update_meta = {"block_status":0}
                voter_obj.update(**update_meta)
                j = merkle_tree.obj_history.index(voter_obj)
                merkle_tree.obj_status[j]=2
                
                transaction_data = {"action": "DELETE","voter_data": new_voter_obj.to_json(), "timestamp": datetime.datetime.now().strftime("%c")}
                transaction = Transaction(writer=user['email'],writer_level = user['level'],details = transaction_data)
                add_transaction(transaction)
                flash("Data deleted successfully",category='success')
                return make_response("Success",200)
        flash("Updation failed",category='error')
        return make_response("Unauthorised Action!",401)


class api_signup(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('signup.html'),200,headers)

    def post(self):
        first_entry = request.form.get('firstName')
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')  
        is_voter = int(request.form.get('voter'))
        headers = {'Content-Type': 'text/html'}
        user = User.objects(email = email).first()
        if user:
            flash('Email id already registered.', category='error')
            print('Email id already registered.')
        elif not is_voter and len(first_entry) < 2:
            flash('Name must be greater than 1 character.', category='error')
            print('Name must be greater than 1 character.')
        elif is_voter and len(first_entry) < 10:
            flash('EPIC ID must contain 10 characters.', category='error')
            print('EPIC ID must contain 10 characters.')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
            print('Email must be greater than 3 characters.')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
            print('Passwords don\'t match.')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
            print('Password must be at least 7 characters.')
        elif is_voter:
            voter = Voter.objects(EPIC_ID = first_entry).first()
            if voter:
                user = User(email = email, password = password1,registered_voter=1,voter=voter)
                user.hash_password()
                user.save()
                flash('User created successfully!', category='success')
                return make_response(render_template('login.html'),204,headers)
            else:
                flash('EPIC ID is invalid', category = 'error')
                return make_response(render_template('signup.html'),400,headers)
        else:
            user = User(email = email, password = password1)
            user.hash_password()
            user.save()
            flash('User created successfully!', category='success')
            return make_response(render_template('login.html'),204,headers)
        return make_response(render_template('signup.html'),400,headers)


class api_login(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('login.html'),200)
        # return make_response("",200)
        
    def post(self):

        email = request.form.get('email')
        password = request.form.get('password')

        # content = request.json
        # email = content['email']
        # password = content['password']

        # email = "hardkaur1632@gmail.com"
        # password = "random"

        user = User.objects(email = email).first()
        headers = {'Content-Type': 'text/html'}
        if user:
            authorized = user.check_password(password)
            if not authorized:
                flash('Incorrect password, try again.', category='error')
                # return make_response("",401)
                return make_response(render_template('login.html'),401)
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
            # return make_response("",200)
            return make_response(render_template('home.html',user=current_user,data=data),200,headers)

        else:
            flash('User doesn\'t exist.', category='error')
            # return make_response("",404)
            return make_response(render_template('login.html'),404,headers)
        
class api_auth_officer(Resource):
    #### HIGHER LEVEL AUTHORISATION REQUIRED ####
    def post(self):
        key = RSA.generate(1024)
        private_key = key.exportKey().decode('utf-8')
        public_key = key.publickey().exportKey().decode('utf-8')

        content = request.json
        content['public_key'] = public_key
        print(public_key)
        pwd = "password"
        if pwd in content:
            pwd = content.pop("password")
        auth_off = Authorised_Officer(**content)
        auth_off.save()
        name_AO = auth_off.name
        path_name =  "~/Desktop/keys/"+name_AO+".txt"
        f = open (os.path.expanduser(path_name),'w')
        f.write(private_key)
        f.close()
        print(private_key)
        user = User.objects(email = content['email']).first()
        if user:
            user.update(level = 2, level_2_id = auth_off, registered_voter = 1)
        else:
            user_data = {"email":content['email'],"password":pwd,"level":2,"level_2_id":auth_off}
            user = User(**user_data)
            user.hash_password()
            user.save()
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


        
    


from flask_bcrypt import generate_password_hash, check_password_hash
from d_b import db
from flask_login import UserMixin
import json
from hashlib import sha256
import datetime 

class Metadata(db.Document):
    writer = db.ReferenceField('User',required=True)
    backward_ptr = db.ReferenceField('Voter')
    timestamp = db.StringField(required = True)
    ### required = True for proof ###
    proof = db.DictField()

    def to_json(self):
        return {
            "writer": self.writer,
            "timestamp": self.timestamp,
            "proof": self.proof
        }

class Voter(db.Document):
    EPIC_ID = db.StringField(required = True)
    name = db.StringField(required = True)
    age = db.IntField(required = True)
    gender = db.StringField(required = True)
    address = db.StringField(required = True)
    father_name = db.StringField(required = True)
    part_number = db.IntField(required = True)
    part_name = db.StringField(required = True)
    assembly_constituency = db.StringField(required = True)
    parliamentary_constituency = db.StringField(required = True)
    assembly_constituency_number = db.IntField(default=0)
    polling_stations = db.ListField(db.StringField(default = []))
    photo = db.ImageField()

    block_status = db.IntField(default = 1)
    forward_ptr = db.ReferenceField('Voter')
    metadata = db.ReferenceField('Metadata')
    prev_hash = db.StringField()
    hash = db.StringField()

    def compute_hash(self):
        """
        A function that return the hash of the entire voter data.
        """
        block_string = json.dumps(self.to_json_complete(), sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


    def to_json(self):
        return {
            "EPIC_ID": self.EPIC_ID,
            "name": self.name,
            "age": self.age,
            "father_name": self.father_name,
            "assembly_constituency": self.assembly_constituency,
            "parliamentary_constituency": self.parliamentary_constituency
        }


    def to_json_complete(self):
        return {
            "EPIC_ID": self.EPIC_ID,
            "name": self.name,
            "age": self.age,
            "gender": self.gender,
            "address": self.address,
            "father_name": self.father_name,
            "part_number" : self.part_number,
            "part_name": self.part_name,
            "assembly_constituency": self.assembly_constituency,
            "assembly_constituency_number": self.assembly_constituency_number,
            "parliamentary_constituency": self.parliamentary_constituency,
            "polling_stations": self.polling_stations
        }


class User(db.Document,UserMixin):
    email = db.EmailField(required = True, unique = True)
    password = db.StringField(required=True, min_length=6)
    level = db.IntField(default = 1) 
    level_2_id = db.ReferenceField('Authorised_Officer')
    registered_voter = db.IntField(default=0)
    voter = db.ReferenceField('Voter',unique=True)

    def to_json(self):
        return {
            "email": self.email,
            "level": self.level
        }

    def hash_password(self):
        self.password = generate_password_hash(self.password).decode('utf8')

    def check_password(self,password):
        return check_password_hash(self.password,password)


class Authorised_Officer(db.Document):
    auth_id = db.StringField(required = True,unique=True)
    email = db.EmailField(required=True)
    name = db.StringField(required = True)
    assembly_constituencies = db.ListField(db.StringField())
    parliamentary_constituencies = db.ListField(db.StringField())


    def to_json(self):
        return {
            "auth_id": self.auth_id,
            "name": self.name,
            "assembly_constituencies": self.assembly_constituencies,
            "parliamentary_constituencies": self.parliamentary_constituencies
        }


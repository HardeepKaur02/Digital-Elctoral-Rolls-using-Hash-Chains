from time import time
from flask import Flask,make_response, request, jsonify
from flask_restful import Resource
from flask_jwt_extended import create_access_token, jwt_required
from d_b import db
from hashlib import sha256
import json
import datetime

THRESHOLD = 0

class Transaction(db.EmbeddedDocument):
    writer = db.EmailField(required = True)
    writer_level = db.IntField(default=1)
    details = db.DictField(required = True)
    def to_json(self):
        return {
            "performed by": self.writer,
            "details": self.details
        }

### transaction: action, writer, timestamp
class Block(db.Document):
    index = db.IntField(required = True, unique=True)
    transactions = db.ListField(db.EmbeddedDocumentField(Transaction), required = True)
    timestamp = db.StringField(required = True)
    previous_hash = db.StringField()
    hash = db.StringField()
    

    # def __init__(self, index, transactions, timestamp, previous_hash):
    #     self.index = index
    #     self.transactions = transactions
    #     self.timestamp = timestamp
    #     self.previous_hash = previous_hash

    def compute_hash(self):
        """
        A function that return the hash of the block contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


class Blockchain:

    def __init__(self):
        self.chain = []

    def init_blockchain(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """
        A function to generate genesis block and appends it to
        the chain. The block has index 0, previous_hash as 0, and
        a valid hash.
        """
        genesis_block = Block(index=0, transactions = [], timestamp= datetime.datetime.now().strftime("%c"),previous_hash = "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        """
        A function that adds the block to the chain after verification.
        Verification includes:
        * Checking if the proof is valid.
        * The previous_hash referred in the block and the hash of latest block
          in the chain match.
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if block.compute_hash() != proof:
            return False

        block.hash = proof
        self.chain.append(block)
        block.save()
        return True



    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)
        if len(self.unconfirmed_transactions) > THRESHOLD:
            self.confirm_transactions()
            self.unconfirmed_transactions = []
            chain_data = []
            for block in blockchain.chain:
                chain_data.append(block.__dict__)
            return json.dumps({"length": len(chain_data),
                            "chain": chain_data})

    def confirm_transactions(self):
        """
        This function serves as an interface to add the pending
        transactions to the blockchain by adding a block containing them.
        """
        last_block = self.last_block
        print(last_block.index)
        new_block = Block(index = (last_block.index + 1),
                        transactions=self.unconfirmed_transactions,
                        timestamp=datetime.datetime.now().strftime("%c"),
                        previous_hash=last_block.hash)
        proof = new_block.compute_hash()
        self.add_block(new_block,proof)


blockchain = Blockchain()
def initialize_blockchain():
    blockchain.init_blockchain()

def add_transaction(transaction):
    blockchain.add_new_transaction(transaction)

class api_immutable_database(Resource):
    @jwt_required()
    def get(self):
        chain_data = []
        for block in blockchain.chain:
            chain_data.append(block.__dict__)
        block = blockchain.last_block
        # if blockchain.is_valid_proof(block,blockchain.proof_of_work()):
        #     print("Data is untampered")
        # else:
        #     print(block.hash, block.compute_hash())
        return json.dumps({"length": len(chain_data),"chain": chain_data})

    @jwt_required()
    def post(self,transactions):
        ### add transactions to block ###
        return blockchain.add_new_transaction(transactions)

    @jwt_required()
    def delete(self):
        return make_response("Forbidden",403)
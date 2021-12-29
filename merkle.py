from hashlib import sha256
import math,json

class MerkleNode:
    """
    Stores the hash and the parent.
    """
    def __init__(self, hash,level=0, leaves = 0):
        self.hash = hash
        self.parent = None
        self.left_child = None
        self.right_child = None
        self.level = level
        self.leaves = leaves


class MerkleTree:
    """
    Stores the leaves and the root hash of the tree.
    """
    def __init__(self, data_chunks):
        self.leaves = []
        for chunk in data_chunks:
            node = MerkleNode(self.compute_hash(chunk),leaves=1)
            self.leaves.append(node)
        self.root = self.build_merkle_tree(self.leaves)
        self.history = {len(self.leaves): self.root.hash}
        self.obj_history = []
        self.obj_status=[]

    def build_merkle_tree(self, leaves,to_print=0):
        """
        Builds the Merkle tree from a list of leaves. In case of an odd number of leaves, the last leaf is duplicated.
        """
        num_leaves = len(leaves)
        if to_print:
            print("WAHEGURU")
            for i in range(num_leaves):
                print(leaves[i].hash)
            print("WAHEGURU")

        if num_leaves == 1:
            return leaves[0]

        parents = []

        i = 0
        while i < num_leaves:
            left_child = leaves[i]
            right_child = leaves[i + 1] if i + 1 < num_leaves else left_child

            parents.append(self.create_parent(left_child, right_child,leaves =  left_child.leaves+right_child.leaves,level = left_child.level +1))

            i += 2

        return self.build_merkle_tree(parents,to_print)

    def extend_tree(self,new_leaves,to_print=0):
        for leaf in new_leaves:
            node = MerkleNode(self.compute_hash(leaf),leaves=1)
            self.leaves.append(node)

        self.root = self.build_merkle_tree(self.leaves,to_print)
        self.history[len(self.leaves)] = self.root.hash

    def create_parent(self, left_child, right_child,leaves=0,level=1):
        parent = MerkleNode(self.compute_hash(left_child.hash + right_child.hash),leaves=leaves,level=level)
        
        parent.left_child, parent.right_child = left_child, right_child
        left_child.parent, right_child.parent = parent, parent

        return parent
    ###
    
    def get_audit_trail(self, chunk_hash):
        """
        Checks if the leaf exists, and returns the audit trail
        in case it does.
        """
        for leaf in self.leaves:
            if leaf.hash == chunk_hash:
                print("Leaf exists")
                return self.generate_audit_trail(leaf,trail=[])
        return False

    def generate_audit_trail(self, merkle_node, trail=[]):
        """
        Generates the audit trail in a bottom-up fashion
        """
        if merkle_node == self.root:
            trail.append([merkle_node.hash,False])
            return trail

        # check if the merkle_node is the left child or the right child
        is_left = merkle_node.parent.left_child == merkle_node
        if is_left:
            # since the current node is left child, right child is
            # needed for the audit trail. We'll need this info later
            # for audit proof.
            trail.append([merkle_node.parent.right_child.hash, False])
            return self.generate_audit_trail(merkle_node.parent, trail)
        else:
            trail.append([merkle_node.parent.left_child.hash, True])
            return self.generate_audit_trail(merkle_node.parent, trail)

    def consistency_proof(self,m):
        # m is the no. of leaves in old tree
        hashnodes = []
        index = int(math.log2(m))
        node = self.leaves[0]  # leftmost leaf
        while index > 0:
            node = node.parent
            index-=1
        k = node.leaves
        print(k)
        print(len(self.leaves))
        hashnodes.append((node.hash,node.level))        
        if m==k:
            return hashnodes
        else:
            sibling = node.parent.right_child
            done = False
            while not done:
                sibling_leaves = sibling.leaves
                if m-k == sibling_leaves:
                    hashnodes.append((sibling.hash,sibling.level))
                    break
                elif m-k > sibling_leaves:
                    hashnodes.append((sibling.hash,sibling.level))
                    sibling = sibling.parent.right_child
                    k += sibling_leaves
                else:
                    sibling = sibling.left_child
        return hashnodes

    @staticmethod
    def compute_hash(data):
        data = data.encode('utf-8')
        return sha256(data).hexdigest()

def data_verification(merkle_tree, leaf_data):
    leaf_hash = MerkleTree.compute_hash(leaf_data)
    audit_trail = merkle_tree.get_audit_trail(leaf_hash)
    if not audit_trail:
        print(leaf_hash)
        print(leaf_data)
        return False
    print(leaf_hash)
    print(audit_trail)
    res = verify_audit_trail(leaf_hash,audit_trail)
    return res

def verify_audit_trail(chunk_hash, audit_trail):
    """
    Performs the audit-proof from the audit_trail received
    from the trusted server.
    """
    proof_till_now = chunk_hash
    for node in audit_trail[:-1]:
        hash = node[0]
        is_left = node[1]
        if is_left:
            # the order of hash concatenation depends on whether the
            # the node is a left child or right child of its parent
            proof_till_now = MerkleTree.compute_hash(hash + proof_till_now)
        else:
            proof_till_now = MerkleTree.compute_hash(proof_till_now + hash)
        print(proof_till_now)
    
    # verifying the computed root hash against the actual root hash
    return proof_till_now == audit_trail[-1][0]

def old_root(trail):
    if len(trail) == 1:
        return 

def verify_consistency(merkle_tree,prev_chunks):
    m = len(prev_chunks)
    print("prev_chunks")
    print(prev_chunks)
    proof_trail = merkle_tree.consistency_proof(m)
    if len(proof_trail) > 1:
        r_hash,r_level = proof_trail[-1]
        i = len(proof_trail)-2
        while i>=0:
            l_hash,l_level = proof_trail[i]
            while l_level != r_level:
                r_hash = MerkleTree.compute_hash(r_hash+r_hash)
                r_level += 1
            r_hash = MerkleTree.compute_hash(l_hash+r_hash)
            i-=1
    else:
        r_hash = proof_trail[0][0]
    print(r_hash,merkle_tree.history)
    return r_hash == merkle_tree.history[m]

def rep(voter_obj,code_str,is_dic=0,active=1):
    if is_dic:
        dic = {"EPIC_ID":voter_obj['EPIC_ID']}
        if(code_str[0]=='1'):
            dic["name"]=voter_obj['name']
        if(code_str[1]=='1'):
            dic["father_name"]=voter_obj['father_name']
        if(code_str[2]=='1'):
            dic["age"]= int(voter_obj['age'])
        if(code_str[3]=='1'):
            dic["gender"]=voter_obj['gender']
        if(code_str[4]=='1'):
            dic["part_number"]= int(voter_obj['part_number'])
        if(code_str[5]=='1'):
            dic["part_name"]=voter_obj['part_name']
        if(code_str[6]=='1'):
            dic["assembly_constituency"]=voter_obj['assembly_constituency']
        if(code_str[7]=='1'):
            dic["parliamentary_constituency"]=voter_obj['parliamentary_constituency']
        return json.dumps(dic)

    dic = {"EPIC_ID":voter_obj.EPIC_ID}
    if(code_str[0]=='1'):
        dic["name"]=voter_obj.name
    if(code_str[1]=='1'):
        dic["father_name"]=voter_obj.father_name
    if(code_str[2]=='1'):
        dic["age"]=int(voter_obj.age)
    if(code_str[3]=='1'):
        dic["gender"]=voter_obj.gender
    if(code_str[4]=='1'):
        dic["part_number"]=int(voter_obj.part_number)
    if(code_str[5]=='1'):
        dic["part_name"]=voter_obj.part_name
    if(code_str[6]=='1'):
        dic["assembly_constituency"]=voter_obj.assembly_constituency
    if(code_str[7]=='1'):
        dic["parliamentary_constituency"]=voter_obj.parliamentary_constituency
    if active!=1:
        print("waheguru maharaj")
        dic["block_status"]=active
    return json.dumps(dic)

# merkle_tree = None
# def main():
# global merkle_tree
# if __name__ == '__main__':
#     main()
#     print(merkle_tree.root.hash)

# file = '01234567'
# chunks = list(file)

# merkle_tree = MerkleTree([chunks[0],])
# for i in range(len(chunks)-1):
#     merkle_tree.extend_tree([chunks[i+1],])
# print(merkle_tree.root.hash)

# chunk_hash = MerkleTree.compute_hash("2")
# print(chunk_hash)
# audit_trail = merkle_tree.get_audit_trail(chunk_hash)
# # audit_trail[0][0] = "0"*64
# print(audit_trail)
# res = verify_audit_trail(chunk_hash, audit_trail)
# print(res)
# new_file = '89'
# new_chunks = list(new_file)
# for i in range(len(new_chunks)):
#     merkle_tree.extend_tree([new_chunks[i],])
# print(merkle_tree.root.hash)
# consistency_trail = merkle_tree.consistency_proof(len(chunks))
# print(consistency_trail)
# chunks_t = list('012345')
# result = verify_consistency(merkle_tree,chunks_t)
# print(result)
from apis import api_auth_officer, api_merkle_tree, api_query_consistency, api_query_membership, api_voter,api_voters,api_db,api_signup,api_login, api_index, api_insert, api_search, api_update, api_delete
from blockchain import api_immutable_database

def initialize_routes(api):
    api.add_resource(api_db, '/api/db_populate')
    api.add_resource(api_voters, '/api/voters')
    api.add_resource(api_voter, '/api/voters/<voter_id>')
    api.add_resource(api_signup, '/api/auth/signup')
    api.add_resource(api_login, '/api/auth/login')
    api.add_resource(api_immutable_database, '/api/immu_db')
    api.add_resource(api_auth_officer, '/api/auth_pro')
    # api.add_resource(api_home, '/api/home')
    api.add_resource(api_index, '/api/index')
    api.add_resource(api_search, '/api/search')
    api.add_resource(api_insert, '/api/insert')
    api.add_resource(api_update, '/api/update')
    api.add_resource(api_delete, '/api/delete')
    api.add_resource(api_merkle_tree, '/api/merkle/consistent')
    api.add_resource(api_query_membership, '/api/merkle/member')
    api.add_resource(api_query_consistency, '/api/merkle/consistent/<num_voters>')
    
    
    
    
    

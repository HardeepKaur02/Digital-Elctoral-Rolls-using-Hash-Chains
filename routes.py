from apis import api_voter,api_voters,api_db,api_signup,api_login
from blockchain import api_immutable_database

def initialize_routes(api):
    api.add_resource(api_db, '/api/db_populate')
    api.add_resource(api_voters, '/api/voters')
    api.add_resource(api_voter, '/api/voters/<voter_id>')
    api.add_resource(api_signup, '/api/auth/signup')
    api.add_resource(api_login, '/api/auth/login')
    api.add_resource(api_immutable_database, '/api/immu_db')
    
    

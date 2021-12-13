from apis import api_voter,api_voters,api_db,api_signup,api_login

def initialize_routes(api):
    api.add_resource(api_db, '/api/db_populate')
    api.add_resource(api_voters, '/api/voters')
    api.add_resource(api_voter, '/api/voters/<voter_id>')
    api.add_resource(api_signup, '/api/auth/signup')
    api.add_resource(api_login, '/api/auth/login')
    
    

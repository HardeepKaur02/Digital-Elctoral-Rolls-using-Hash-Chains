Digital Electoral Rolls

This is an attempt towards implementing Digital Electoral Rolls in a privacy preserving manner. It uses cryptographic primitives like digital signatures, hash pointers, merkle trees, immutable ledger and append only database to provide non-repudiation, auditability, tamper evidence, immutabililty and data integrity.  

Setup
Follow the given steps to make this code work: 

1. Ensure that you have python on your system.
2. Create an account on MongoDB Atlas.
3. Craete a cluster from your account.
4. Craete a database named 'Electoral_Rolls' and collection named 'user' in the cluster.
5. Set the DB_URI field in 'app.py' to connect the cluster to the application.
6. Save the password for database in 'api_constants.py'.
7. Run installer.py for installing the required libraries.

Whoa! You are ready to run the code :)

Run app.py and access the electoral roll api at http://127.0.0.1:5000/api/index.
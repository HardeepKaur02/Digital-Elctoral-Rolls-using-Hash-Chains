import sys
import subprocess

# implement pip as a subprocess:
packages = ['flask','flask-restful','flask-jwt-extended','flask-login','pycryptodome','flask-mongoengine','flask-bcrypt']
for package in packages:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
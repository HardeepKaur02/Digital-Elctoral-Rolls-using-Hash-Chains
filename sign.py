#### rough implementation of digital signatures

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import codecs

key = RSA.generate(1024)
# private_key = key.exportKey()
# public_key = key.publickey().exportKey()
# # print(private_key)
# # print(public_key)
# file1 = open('certificate.txt','w')
# file1.write(private_key.decode('utf-8'))
# file1.close()
# file2 = open('certificate2.txt','w')
# file2.write(public_key.decode('utf-8'))
# file2.close()


message = "HI THERE"
h = SHA256.new(message.encode("utf8"))
file1 = open('certificate.txt')
private_key = file1.read().encode("utf-8")

file2 = open('certificate2.txt')
public_key = file2.read().encode("utf-8")

priv_key = RSA.importKey(private_key)
pub_key = RSA.importKey(public_key)
signer = PKCS1_v1_5.new(priv_key)
signature = signer.sign(h)
print(signature)
print(type(signature))

# hexify = codecs.getencoder('hex')
# m = hexify(signature)[0]
# print(m)

# hexify_back = codecs.getdecoder('hex')
# signature_2 = hexify_back(m)[0]
# print(signature_2)
# print(signature==signature_2)
verifier = PKCS1_v1_5.new(pub_key)
print(verifier.verify(h,signature))
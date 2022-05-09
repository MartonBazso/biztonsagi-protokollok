

import sys
import binascii
import argon2
import json
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto import Random

username, password = sys.argv[1],  sys.argv[2]

outputfile = "users.txt"
password = bytes(password, "utf-8")

salt = b'crysys salt'

pass_hash = argon2.hash_password_raw(password=password, salt=salt)

dict_users = dict()

with open(outputfile, "r") as file:
    s = file.read()
    dict_users = json.loads(s)


dict_users[username] = str(pass_hash.hex())

with open(outputfile, "w") as file:
    file.write(json.dumps(dict_users))




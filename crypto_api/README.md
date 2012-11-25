crypto_api
==========

Python encryption utility library, a wrapper around PyCrypto. And a save-able user object.


License
===========

<pre>
This source code is licensed under the GNU General Public License,
Version 3. http://www.gnu.org/licenses/gpl-3.0.en.html

Copyright (C)

Erik de Jonge <erik@a8.nl>
Actve8 BV
Rotterdam
www.a8.nl
</pre>


Features
===========

* single value encryption
* array encryption
* rsa encryption
* rsa signing
* a user object with PBKDF2 password hashing and rsa key generation


Dependency
===========

https://github.com/erikdejonge/couchdb_api

https://www.dlitz.net/software/pycrypto/


Workings
===========

*encryption*

```python
key = "your password"

# single value encryption
test_encryption_scalar(key, "Hello world"):

# array encryption
test_encryption_array(key, ["Hello world", "Goodbye world"]):
```

*signing*

```python
# generate key pair
rsa_key_pair = RSA.generate(1024)
private_key = rsa_key_pair.exportKey()
public_key = rsa_key_pair.publickey().publickey().exportKey()

# sign data
signature = sign(private_key, data)

# verify the data
verify(public_key, data, signature)
```

*user*

```python
# get a couchdb database object
dbase = couchdb_api.CouchDBServer("crypto_api_test")

# make a user
user = User(dbase, object_id="John")
key = "a password here"

# load or create a user
if user.exists():
    print "loading user"
    user.load()
else:
    print "creating user"
    user.create_user(key)

# authorize the user
try:
    user.authorize(key)
except PasswordException, ex:
    print ex

# encrypt some data with users public key
data = "hello world"
user.encrypt_with_public_key(data)

# delete user
user.delete()
```

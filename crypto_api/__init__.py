# coding=utf-8

"""

Python encryption utility library, a wrapper around PyCrypto. And a save-able user object.

This source code is licensed under the GNU General Public License,
Version 3. http://www.gnu.org/licenses/gpl-3.0.en.html

Copyright (C)

Erik de Jonge <erik@a8.nl>
Actve8 BV
Rotterdam
www.a8.nl

"""

import zlib
import cPickle
import base64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC
import couchdb_api
import time
import os

def log(msg):
    """
    log a message in a dict to see all characters

    @param msg: log msg
    @type msg: string
    """

    spl = str({"msg": msg}).replace("{'msg': '", "").replace("'}", "").split(":")
    for i in spl:
        if i != spl[len(spl) - 1]:
            print i + ":", "\t",
        else:
            print i, "\t"


#noinspection PyArgumentEqualDefault
def encrypt(key, data, data_is_list=False, perc_callback=None, perc_callback_freq=0.1, pbkdf2_iters=1000):
    """
    encrypt data or a list of data with the password (key)

    @param key: secret key or password
    @type key: string
    @param data: data to encrypt
    @type data: list, bytearray
    @param data_is_list: is the data a list
    @type data_is_list: bool
    @param perc_callback: callback function
    @type perc_callback: callable
    @param perc_callback_freq: seconds to wait untill next callbacl call
    @type perc_callback_freq: float
    @type perc_callback: callable
    @param pbkdf2_iters: pbkdf2 password enhancer iterations, default 1000
    @type pbkdf2_iters: int
    @return: ecnrypted data dict
    @rtype: dict
    """

    if not data:
        raise Exception("encrypt: data is None")

    # the block size for the cipher object; must be 16, 24, or 32 for AES

    block_size = 32

    # the character used for padding--with a block cipher such as AES, the value
    # you encrypt must be a multiple of block_size in length.  This character is
    # used to ensure that your value is always a multiple of block_size

    padding = "{"

    # one-liner to sufficiently pad the text to be encrypted

    pad = lambda s: s + (block_size - len(s) % block_size) * padding

    # enhance secret

    salt = Random.new().read(100)
    secret = PBKDF2(key, salt, 32, pbkdf2_iters)

    # create a cipher object using the random secret

    initialization_vector = Random.new().read(AES.block_size)
    cipher = AES.new(secret, AES.MODE_CFB, IV=initialization_vector)

    # encode the list or string
    lc_time = time.time()
    if data_is_list:
        hash = make_hash_str(data[0:5])
        encoded_data = []
        total = len(data)
        cnt = 0
        for data in data:
            cnt += 1
            encoded_data.append(cipher.encrypt(pad(data)))
            if perc_callback:
                if time.time() - lc_time > perc_callback_freq:
                    perc_callback(cnt / (float(total) / 100))
                    lc_time = time.time()
    else:
        hash = make_hash_str(data[0:100])
        encoded_data = cipher.encrypt(pad(data))

    encrypted_data_dict = {
        "salt": salt,
        "hash": hash,
        "initialization_vector": initialization_vector,
        "encoded_data": encoded_data
    }
    if encoded_data == data:
        raise Exception("encrypt: Data is not encrypted")
    return encrypted_data_dict


class EncryptionHashMismatch(Exception):
    """
    raised when the hash of the decrypted data doesn't match the hash of the original data
    """
    pass

#noinspection PyArgumentEqualDefault
def decrypt(key, encrypted_data_dict, data_is_list=False, perc_callback=None, perc_callback_freq=0.1, pbkdf2_iters=1000):
    """
    encrypt data or a list of data with the password (key)

    @param key: password
    @type key: string
    @param encrypted_data_dict: encrypted data
    @type encrypted_data_dict: dict
    @param data_is_list: is it a list
    @type data_is_list: bool
    @param perc_callback: callback function
    @type perc_callback: callable
    @param pbkdf2_iters: pbkdf2 password enhancer iterations, default 1000
    @type pbkdf2_iters: int
    @param perc_callback_freq: seconds to wait untill next callbacl call
    @type perc_callback_freq: float
    @return: the data
    @rtype: list, bytearray
    """

    # the character used for padding--with a block cipher such as AES, the value
    # you encrypt must be a multiple of block_size in length.  This character is
    # used to ensure that your value is always a multiple of block_size

    padding = "{"

    # one-liners to encrypt/encode and decrypt/decode a string
    # encrypt with AES, encode with base64
    # enhance secret

    secret = PBKDF2(key, encrypted_data_dict["salt"], 32, pbkdf2_iters)

    # create a cipher object using the random secret
    # initialization_vector = Random.new().read(AES.block_size)

    assert 16 == len(encrypted_data_dict["initialization_vector"]), "initialization_vector len is not 16"

    cipher = AES.new(secret, AES.MODE_CFB, encrypted_data_dict["initialization_vector"])

    # decide the list or string
    lc_time = time.time()
    if data_is_list:
        decoded = []
        total = len(encrypted_data_dict["encoded_data"])
        cnt = 0
        for data in encrypted_data_dict["encoded_data"]:
            decoded.append(cipher.decrypt(data).rstrip(padding))
            if perc_callback:
                if time.time() - lc_time > perc_callback_freq:
                    perc_callback(cnt / (float(total) / 100))
                    lc_time = time.time()
            cnt += 1
    else:
        decoded = cipher.decrypt(encrypted_data_dict["encoded_data"]).rstrip(padding)

    if data_is_list:
        hash = make_hash_str(decoded[0:5])
    else:
        hash = make_hash_str(decoded[0:100])
    if "hash" in encrypted_data_dict:
        if hash != encrypted_data_dict["hash"]:
            raise EncryptionHashMismatch("the decryption went wrong, hash didn't match")
    return decoded


def decrypt_array_of_data(key, enc_lines, perc_callback=None, perc_callback_freq=0.1):
    """
    decrypt a string to a list a chink of data

    @param key:
    @param enc_lines:
    @param perc_callback:
    @param perc_callback_freq:
    """
    data = None
    data_list = decrypt(key, enc_lines, True, perc_callback, perc_callback_freq)
    for chunk in data_list:
        if not data:
            data = chunk
        else:
            data += chunk
    return data


def decrypt_file(key, enc_filename, perc_callback=None, perc_callback_freq=0.1):
    """
    decrypt a file to a file without .enc extension

    @param key:
    @param enc_filename:
    @param perc_callback:
    @param perc_callback_freq:
    """
    enc_file = pickled_base64_to_object(open(enc_filename, "r").read())
    data = decrypt_array_of_data(key, enc_file, perc_callback, perc_callback_freq)
    filename = enc_filename.rstrip(".enc")
    open(filename, "w").write(data)
    return filename


def encrypt_file_to_string(key, filename, perc_callback=None, perc_callback_freq=0.1):
    """
    encrypt a file

    @param key:
    @param filename:
    @param perc_callback:
    @param perc_callback_freq:
    """
    lines = []
    with open(filename, "r") as fin:
        chunk = fin.read(1000000)
        while chunk != "":
            lines.append(chunk)
            chunk = fin.read(1000000)
    encrypted_file = encrypt(key, lines, True, perc_callback, perc_callback_freq)
    return object_to_pickled_base64(encrypted_file)


def encrypt_file(key, fname, perc_callback=None, perc_callback_freq=0.1):
    """
    encrypt a file to an .enc file

    @param key:
    @param fname:
    @param perc_callback:
    @param perc_callback_freq:
    """
    enc_filename = fname + ".enc"
    fout = open(enc_filename, "w")
    fout.write(encrypt_file_to_string(key, fname, perc_callback, perc_callback_freq))
    return enc_filename


def get_aes_speed(key, filesize_in_mb, perc_callback):
    """
    test speed

    @param key:
    @param filesize_in_mb:
    @param perc_callback:
    """
    os.system("dd if=/dev/zero of=output.dat  bs=1024  count=1024*" + str(filesize_in_mb))
    start = time.time()
    encrypt_file(key, "output.dat", perc_callback, 0.5)
    duration = time.time() - start
    os.system("rm output.dat")
    os.system("rm output.dat.enc")
    return duration


def make_hash(data):
    """ make hash
    @param data:
    """
    m = md5.new()
    m.update(data)
    return m.digest()

    hmac = HMAC.new(data)
    return hmac.hexdigest()


import md5
def make_hash_str(data):
    """ make hash
    @param data:
    """


    m = md5.new()
    m.update(str(data))
    return m.digest()

    #hmac = HMAC.new(str(data))
    #return hmac.hexdigest()


def sign(private_key, data):
    """ hash data and sign the hash

    @param private_key:
    @param data:
    """

    private_key = private_key.strip()
    ahash = make_hash(data)
    private_key = RSA.importKey(private_key)
    return private_key.sign(ahash, Random.new().read(100))


def verify(public_key, data, signature):
    """ hash data and verify against signature

    @param public_key:
    @param data:
    @param signature:
    """

    public_key = public_key.strip()
    ahash = make_hash(data)
    public_key = RSA.importKey(public_key)
    return public_key.verify(ahash, signature)


class PasswordException(Exception):
    """ password has doesn't match the stored hash """

    pass


def object_to_pickled_base64(obj):
    """ convert object to base64

    @param obj:
    """

    return base64.b64encode(zlib.compress(cPickle.dumps(obj, cPickle.HIGHEST_PROTOCOL), 9))


def pickled_base64_to_object(p64):
    """ base64 to object

    @param p64:
    """

    return cPickle.loads(zlib.decompress(base64.b64decode(p64)))


def encrypt_object(key, obj, pbkdf2_iters=1000):
    """ convert to base64 and encrypt

    @param key:
    @param obj:
    @param pbkdf2_iters: pbkdf2 password enhancer iterations, default 1000
    @type pbkdf2_iters: int
    """

    return base64.b64encode(cPickle.dumps(encrypt(key, zlib.compress(cPickle.dumps(obj, cPickle.HIGHEST_PROTOCOL), 9), pbkdf2_iters=pbkdf2_iters)))


def decrypt_object(key, obj_string, pbkdf2_iters=1000):
    """ encrypted base64 to object

    @param key:
    @param obj_string:
    @param pbkdf2_iters: pbkdf2 password enhancer iterations, default 1000
    @type pbkdf2_iters: int
    """

    return cPickle.loads(zlib.decompress(decrypt(key, cPickle.loads(base64.b64decode(obj_string)), pbkdf2_iters=pbkdf2_iters)))


class User(couchdb_api.SaveObject):
    """ user object with encrypted rsa private key, encrypted salt and PBKDF2 password hash """

    password = None
    m_password_hash_p64s = None
    m_encrypted_salt_p64s = None
    rsa_private_key = None
    m_rsa_public_key = None
    salt = None
    m_aes_encrypted_rsa_private_key_p64s = None
    authorized = False

    def __init__(self, dbase, object_id, comment="a cryptobox user"):
        super(User, self).__init__(dbase, object_id, comment)

    def get_name(self):
        """
        objectid is username
        """
        return self.object_id

    def load(self, dbase=None, object_id=None):
        """
        load the user object from couch

        @param dbase:
        @param object_id:
        """
        if object_id:
            self.object_id = object_id
        if dbase:
            self._dbase = dbase
        return super(User, self).load(object_id=self.object_id)

    def _check_password(self, password):
        """ some password rules
        @param password:
        """

        try:
            if len(self.object_id) <= 0:
                raise Exception("username not set")
            if len(password) < 16:
                raise PasswordException("Password should contain at least 16 characters")
            if len(password.split(" ")) < 4:
                raise PasswordException("Password should contain at least 4 words")
            uppers = [c for c in password if c.isupper()]
            if len(uppers) < 2:
                raise PasswordException("Password should contain at least 2 uppercase letters")
        except PasswordException, ex:
            log("Weak password:" + str(ex))

    #noinspection PyArgumentEqualDefault
    def reset_password(self, new_password):
        """ decrypt salt, decrypt rsa private key, make new password hash and re-encrypt

        @param new_password:
        """

        if not self.authorized:
            raise Exception("decrypt_with_private_key: user not authorized")
        self._check_password(new_password)
        self.salt = decrypt(self.password, self.m_encrypted_salt_p64s)
        self.rsa_private_key = self.get_rsa_private_key()
        self.password = new_password
        self.m_encrypted_salt_p64s = encrypt(key=self.password, data=self.salt)
        self.m_password_hash_p64s = PBKDF2(self.password, self.salt, 128, 1000)
        self.m_aes_encrypted_rsa_private_key_p64s = encrypt(key=self.password, data=self.rsa_private_key)
        self.save()

    #noinspection PyArgumentEqualDefault
    def create_user(self, password):
        """ make rsa keypair and encrypt private key

        @param password:
        """

        if not self.object_id:
            raise Exception("create_user: username not set")

        self._check_password(password)
        self.password = password

        # make a salt and encrypt that too

        self.salt = Random.new().read(2048)
        self.m_encrypted_salt_p64s = encrypt(key=self.password, data=self.salt)
        self.m_password_hash_p64s = PBKDF2(self.password, self.salt, 128, 1000)

        # make key pair for user

        rsa_key_pair = RSA.generate(1024)
        self.rsa_private_key = rsa_key_pair.exportKey()
        self.m_aes_encrypted_rsa_private_key_p64s = encrypt(key=self.password, data=self.rsa_private_key)
        self.m_rsa_public_key = rsa_key_pair.publickey().publickey().exportKey()
        self.authorized = True

    def get_rsa_private_key(self):
        """ decrypt private key """

        if not self.authorized:
            raise Exception("get_rsa_private_key: user not authorized")
        if not self.rsa_private_key:
            self.rsa_private_key = decrypt(self.password, self.m_aes_encrypted_rsa_private_key_p64s)
        return self.rsa_private_key

    def get_password_hash_b64(self):
        """
            get the passwordhash base64 encoded
        """

        return base64.encodestring(self.m_password_hash_p64s)

    #noinspection PyArgumentEqualDefault
    def authorize(self, password=None, password_hash_b64=None):
        """ match provided password against stored hash

        @param password:
        @param password_hash_b64:
        """

        self.password = password
        if not self.m_encrypted_salt_p64s:
            raise PasswordException("authorize error: user not loaded")
        if password_hash_b64:
            password_hash = base64.decodestring(password_hash_b64)
            if password_hash == self.m_password_hash_p64s:
                self.authorized = True
                return True
            raise PasswordException(self.object_id + " is not authorized")
        else:
            if not password:
                raise PasswordException("password is not given")
        self.salt = decrypt(self.password, self.m_encrypted_salt_p64s)
        password_hash = PBKDF2(self.password, self.salt, 128, 1000)
        if password_hash == self.m_password_hash_p64s:
            self.authorized = True
            return True
        raise PasswordException(self.object_id + " is not authorized")

    def encrypt_with_public_key(self, data):
        """ RSAES-OAEP encrypt

        @param data:
        """

        if not self.m_rsa_public_key:
            self.load()
        return PKCS1_OAEP.new(RSA.importKey(self.m_rsa_public_key)).encrypt(data)

    def decrypt_with_private_key(self, enc_data):
        """ RSAES-OAEP decrypt

        @param enc_data:
        """

        if not self.authorized:
            raise Exception("decrypt_with_private_key: user not authorized")
        return PKCS1_OAEP.new(RSA.importKey(self.get_rsa_private_key())).decrypt(enc_data)

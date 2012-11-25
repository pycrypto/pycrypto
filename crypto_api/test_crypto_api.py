# coding=utf-8

"""
    test progream
"""

import os
import time
import couchdb_api
from Crypto import Random
from Crypto.PublicKey import RSA
from __init__ import *


def test_encryption_scalar(key, data):
    """
        test single value encryption
    :param key:
    :param data:
    @param key:
    @param data:
    """
    encrypted_data_dict = encrypt(key, data)
    decdata = decrypt(key, encrypted_data_dict)
    print "test_encryption_scalar", decdata, " == ", data
    return data == decdata


def test_encryption_array(key, data):
    """
        test encryption of entire array
    :param key:
    :param data:
    @param key:
    @param data:
    """
    encrypted_data_dict = encrypt(key, data, data_is_list=True)
    decdata = decrypt(key, encrypted_data_dict, data_is_list=True)
    print "test_encryption_array", decdata, " == ", data
    return data == decdata


def test_public_private_key_enc(user, data):
    """
        test rsa encryption
    :param user:
    :param data:
    @param user:
    @param data:
    """
    enc_data = user.encrypt_with_public_key(data)
    dec_data = user.decrypt_with_private_key(enc_data)
    print "test_private_key_enc", dec_data, " == ", data
    return data == dec_data


def enc_callback(perc):
    """
        test
    :param perc:
    @param perc:
    """
    print "encrypting:", perc, "%"


def dec_callback(perc):
    """
        test
    :param perc:
    @param perc:
    """
    print "decrypting:", perc, "%"


def test_file_encryption(key, filename):
    """
        encrypt a file
    :param key:
    :param filename:
    @param key:
    @param filename:
    """
    org_data = open(filename, "r").read()
    enc_filename = encrypt_file(key, filename, enc_callback)
    filename = decrypt_file(key, enc_filename, dec_callback)
    org_data_dec = open(filename, "r").read()

    return org_data == org_data_dec


def sign(private_key, data):
    """
        test rsa signing
    :param private_key:
    :param data:
    @param private_key:
    @param data:
    """
    private_key = private_key.strip()
    ahash = make_hash(data)
    private_key = RSA.importKey(private_key)
    return private_key.sign(ahash, Random.new().read(100))


def verify(public_key, data, signature):
    """
        test verifying rsa
    :param public_key:
    :param data:
    :param signature:
    @param public_key:
    @param data:
    @param signature:
    """
    public_key = public_key.strip()
    ahash = make_hash(data)
    public_key = RSA.importKey(public_key)
    return public_key.verify(ahash, signature)


def user_test(dbase, new_user, key, new_key):
    """
        test user object
    :param dbase:
    :param new_user:
    :param key:
    :param new_key:
    @param dbase:
    @param new_user:
    @param key:
    @param new_key:
    """
    print
    print "--------------------"
    print "USER"
    user = User(dbase, object_id="rabshakeh")
    if new_user:
        user.delete()

    if user.exists():
        print "loading user"
        user.load()
    else:
        print "creating user"
        user.create_user(key)

    print "authorizing"
    password_hash = user.get_password_hash_b64()
    user.authorize(key, password_hash_b64=password_hash)

    try:
        user.authorize(key)
    except PasswordException, ex:
        print ex

        # swap

        (key, new_key) = (new_key, key)
        user.authorize(key)

    if not test_public_private_key_enc(user, "Hello world RSA"):
        raise Exception("private key encryption failed")

    print "user pw hash", {1: user.m_password_hash_p64s}
    data = "hello city"
    enc_data = user.encrypt_with_public_key(data)

    # now reset the password

    user.reset_password(new_key)

    # try to decrypt public key message with

    user2 = User(dbase, object_id="rabshakeh")
    user2.load()
    user2.authorize(new_key)

    print "rsa_decrypt_new_pw_rsa:", data == user2.decrypt_with_private_key(enc_data)


def signing():
    """
        test rsa signing
    """
    print
    print "--------------------"
    print "SIGNING"
    print "generating key"
    rsa_key_pair = RSA.generate(1024)
    private_key = rsa_key_pair.exportKey()
    print private_key
    public_key = rsa_key_pair.publickey().publickey().exportKey()
    print public_key

    start = time.time()
    print "opening 10 mb file"
    data = open("README.md", "r").read()
    print "sign 10 mb"
    signature = sign(private_key, data)
    print "verify same data"
    print "data unchanged", verify(public_key, data, signature)
    data += "1"
    print "verify changed data"
    print "data unchanged", verify(public_key, data, signature)
    print "verfifying 10 mb done in ", time.time() - start


def fileenc(key):
    """
        test file encryption
    :param key:
    @param key:
    """
    print
    print "--------------------"
    print "ENCRYPTION"

    filesize_in_mb = 2
    print
    print "One moment, making", filesize_in_mb, "mb file"
    os.system("dd if=/dev/zero of=output.dat  bs=1024  count=1024*" + str(filesize_in_mb))
    print "Start encryption of file 'output.dat'"
    if not test_file_encryption(key, "output.dat"):
        raise Exception("file encryption failed")
    os.system("rm output.dat")
    os.system("rm output.dat.enc")
    print "file encryption ok"
    print

    if not test_encryption_scalar(key, "Hello world"):
        raise Exception("scalar encryption failed")

    if not test_encryption_array(key, ["Hello world", "Goodbye world"]):
        raise Exception("array encryption failed")

    print "Speedtest 20MB"
    speed = get_aes_speed(key, 20, enc_callback)
    print "File enc speed 20mb ->", speed


def main():
    """
        main function
    """
    named_cluster = couchdb_api.CouchNamedCluster("couchdb_api_test", ["http://127.0.0.1:5984/"])
    dbase = couchdb_api.CouchDBServer()
    dbase.create(named_cluster)
    key = "This is A Long password, 777"
    new_key = "This is also A Long password, 1234678"

    user_test(dbase, False, key, new_key)

    signing()
    fileenc(key)

    print "deleting database"
    import couchdb

    for server in named_cluster.get_servers():
        couchdb.Server(server).delete(named_cluster.get_name())

    s = "hello world"
    s1 = encrypt("x", s)
    try:
        print "testing decrypting with wrong password"
        s2 = decrypt("a", s1)
        print s == s2
    except EncryptionHashMismatch, ex:
        print "this should fail -> ", ex
        s2 = decrypt("x", s1)
        print s == s2


def main2():
    d = {"hello":"world", "hello1":"world", "hello2":"world", "hello3":"world", "hello4":"world", "een":1, 2:"twee"}
    #s = object_to_pickled_base64(d)
    #pickled_base64_to_object(s)

    for i in range(0, 10):
        s = encrypt_object("k", d)
        decrypt_object("k", s)

if __name__ == "__main__":
    main2()

from Crypto.PublicKey import RSA
from Crypto.Util.randpool import RandomPool
from datetime import date
import base64, os, pickle

def gen_new_key(size=1024):
  pool =  RandomPool()
  pool.randomize()
  pool.stir_n(5)
  key = RSA.generate(1024, pool.get_bytes)   # This will take a while...
  return key

def load_key(filename):
  f=open(filename, "rb")
  b64str=f.read(4096)
  str = base64.b64decode(b64str)
  key = pickle.loads(str)
  return key  
  

def save_key(key, filename):
  str = pickle.dumps(key)
  if os.path.exists(filename):
     raise Exception("File already exists : %s" % filename)
  f = open(filename, "wb")
  f.write(base64.b64encode(str))
  f.close() 


def load_key(filename):
  f=open(filename, "rb")
  b64str=f.read(4096)
  str = base64.b64decode(b64str)
  key = pickle.loads(str)
  return key  



key = gen_new_key()
save_key(key, "TEST")
save_key(key.publickey(), "TEST.pub")


print "Loading private key"
k = load_key("TEST")
print "Loading public key"
pk = load_key("TEST.pub")



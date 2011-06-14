
/* -*- C -*- */
/*
 *  block_template.c : Generic framework for block encryption algorithms
 *
 * Written by Andrew Kuchling and others
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain.  To
 * the extent that dedication to the public domain is not available,
 * everyone is granted a worldwide, perpetual, royalty-free,
 * non-exclusive license to exercise all rights associated with the
 * contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ===================================================================
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _HAVE_STDC_HEADERS
#include <string.h>
#endif

#include "Python.h"
#include "modsupport.h" 

#include "_counter.h"

/* Cipher operation modes */

#define MODE_ECB 1
#define MODE_CBC 2
#define MODE_CFB 3
#define MODE_PGP 4
#define MODE_OFB 5
#define MODE_CTR 6

#define _STR(x) #x
#define _XSTR(x) _STR(x)
#define _PASTE(x,y) x##y
#define _PASTE2(x,y) _PASTE(x,y)
#define _MODULE_NAME _PASTE2(init,MODULE_NAME)
#define _MODULE_STRING _XSTR(MODULE_NAME)

typedef struct 
{
	PyObject_HEAD 
	int mode, count, segment_size;
	unsigned char IV[BLOCK_SIZE], oldCipher[BLOCK_SIZE];
	PyObject *counter;
	int counter_shortcut;
	block_state st;
} ALGobject;

staticforward PyTypeObject ALGtype;

#define is_ALGobject(v)		((v)->ob_type == &ALGtype)

static ALGobject *
newALGobject(void)
{
	ALGobject * new;
	new = PyObject_New(ALGobject, &ALGtype);
	new->mode = MODE_ECB;
	new->counter = NULL;
	new->counter_shortcut = 0;
	return new;
}

static void
ALGdealloc(PyObject *ptr)
{		
	ALGobject *self = (ALGobject *)ptr;

	/* Overwrite the contents of the object */
	Py_XDECREF(self->counter);
	self->counter = NULL;
	memset(self->IV, 0, BLOCK_SIZE);
	memset(self->oldCipher, 0, BLOCK_SIZE);
	memset((char*)&(self->st), 0, sizeof(block_state));
	self->mode = self->count = self->segment_size = 0;
	PyObject_Del(ptr);
}


static char ALGnew__doc__[] = 
"new(key, [mode], [IV]): Return a new " _MODULE_STRING " encryption object.";

static char *kwlist[] = {"key", "mode", "IV", "counter", "segment_size",
#ifdef PCT_ARC2_MODULE
                         "effective_keylen",
#endif
			 NULL};

static ALGobject *
ALGnew(PyObject *self, PyObject *args, PyObject *kwdict)
{
	unsigned char *key, *IV;
	ALGobject * new=NULL;
	int keylen, IVlen=0, mode=MODE_ECB, segment_size=0;
	PyObject *counter = NULL;
	int counter_shortcut = 0;
#ifdef PCT_ARC2_MODULE
        int effective_keylen = 1024;    /* this is a weird default, but it's compatible with old versions of PyCrypto */
#endif
	/* Set default values */
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "s#|is#Oi"
#ifdef PCT_ARC2_MODULE
					 "i"
#endif
					 , kwlist,
					 &key, &keylen, &mode, &IV, &IVlen,
					 &counter, &segment_size
#ifdef PCT_ARC2_MODULE
					 , &effective_keylen
#endif
		)) 
	{
		return NULL;
	}

	if (KEY_SIZE!=0 && keylen!=KEY_SIZE)
	{
		PyErr_Format(PyExc_ValueError, 
			     "Key must be %i bytes long, not %i",
			     KEY_SIZE, keylen);
		return NULL;
	}
	if (KEY_SIZE==0 && keylen==0)
	{
		PyErr_SetString(PyExc_ValueError, 
				"Key cannot be the null string");
		return NULL;
	}
	if (IVlen != BLOCK_SIZE && IVlen != 0)
	{
		PyErr_Format(PyExc_ValueError, 
			     "IV must be %i bytes long", BLOCK_SIZE);
		return NULL;
	}
	if (mode<MODE_ECB || mode>MODE_CTR) 
	{
		PyErr_Format(PyExc_ValueError, 
			     "Unknown cipher feedback mode %i",
			     mode);
		return NULL;
	}

	/* Mode-specific checks */
	if (mode == MODE_CFB) {
		if (segment_size == 0) segment_size = 8;
		if (segment_size < 1 || segment_size > BLOCK_SIZE*8 || ((segment_size & 7) != 0)) {
			PyErr_Format(PyExc_ValueError, 
				     "segment_size must be multiple of 8 (bits) "
				     "between 1 and %i", BLOCK_SIZE*8);
			return NULL;
		}
	}

	if (mode == MODE_CTR) {
		if (counter == NULL) {
			PyErr_SetString(PyExc_TypeError,
					"'counter' keyword parameter is required with CTR mode");
			return NULL;
		} else if (PyObject_HasAttrString(counter, "__PCT_CTR_SHORTCUT__")) {
			counter_shortcut = 1;
		} else if (!PyCallable_Check(counter)) {
			PyErr_SetString(PyExc_ValueError, 
					"'counter' parameter must be a callable object");
			return NULL;
		}
	} else {
		if (counter != NULL) {
			PyErr_SetString(PyExc_ValueError, 
					"'counter' parameter only useful with CTR mode");
			return NULL;
		}
	}

	/* Cipher-specific checks */
#ifdef PCT_ARC2_MODULE
        if (effective_keylen<0 || effective_keylen>1024) {
		PyErr_Format(PyExc_ValueError,
			     "RC2: effective_keylen must be between 0 and 1024, not %i",
			     effective_keylen);
		return NULL;
        }
#endif

	/* Copy parameters into object */
	new = newALGobject();
	new->segment_size = segment_size;
	new->counter = counter;
	Py_XINCREF(counter);
	new->counter_shortcut = counter_shortcut;
#ifdef PCT_ARC2_MODULE
        new->st.effective_keylen = effective_keylen;
#endif

	block_init(&(new->st), key, keylen);
	if (PyErr_Occurred())
	{
		Py_DECREF(new);
		return NULL;
	}
	memset(new->IV, 0, BLOCK_SIZE);
	memset(new->oldCipher, 0, BLOCK_SIZE);
	memcpy(new->IV, IV, IVlen);
	new->mode = mode;
	switch(mode) {
	case MODE_PGP:
	    new->count=8;
	    break;
	case MODE_CTR:
	default:
	    new->count=BLOCK_SIZE;   /* stores how many bytes in new->oldCipher have been used */
	}
	return new;
}

static char ALG_Encrypt__doc__[] =
"Encrypt the provided string of binary data.";

static PyObject *
ALG_Encrypt(ALGobject *self, PyObject *args)
{
	unsigned char *buffer, *str;
	unsigned char temp[BLOCK_SIZE];
	int i, j, len;
	PyObject *result;
  
	if (!PyArg_Parse(args, "s#", &str, &len))
		return NULL;
	if (len==0)			/* Handle empty string */
	{
		return PyString_FromStringAndSize(NULL, 0);
	}
	if ( (len % BLOCK_SIZE) !=0 && 
	     (self->mode!=MODE_CFB) && (self->mode!=MODE_PGP) &&
	     (self->mode!=MODE_CTR))
	{
		PyErr_Format(PyExc_ValueError, 
			     "Input strings must be "
			     "a multiple of %i in length",
			     BLOCK_SIZE);
		return NULL;
	}
	if (self->mode == MODE_CFB && 
	    (len % (self->segment_size/8) !=0)) {
		PyErr_Format(PyExc_ValueError, 
			     "Input strings must be a multiple of "
			     "the segment size %i in length",
			     self->segment_size/8);
		return NULL;
	}

	buffer=malloc(len);
	if (buffer==NULL) 
	{
		PyErr_SetString(PyExc_MemoryError, 
				"No memory available in "
				_MODULE_STRING " encrypt");
		return NULL;
	}
	Py_BEGIN_ALLOW_THREADS;
	switch(self->mode)
	{
	case(MODE_ECB):      
		for(i=0; i<len; i+=BLOCK_SIZE) 
		{
			block_encrypt(&(self->st), str+i, buffer+i);
		}
		break;

	case(MODE_CBC):      
		for(i=0; i<len; i+=BLOCK_SIZE) 
		{
			for(j=0; j<BLOCK_SIZE; j++)
			{
				temp[j]=str[i+j]^self->IV[j];
			}
			block_encrypt(&(self->st), temp, buffer+i);
			memcpy(self->IV, buffer+i, BLOCK_SIZE);
		}
		break;

	case(MODE_CFB):      
		for(i=0; i<len; i+=self->segment_size/8) 
		{
			block_encrypt(&(self->st), self->IV, temp);
			for (j=0; j<self->segment_size/8; j++) {
				buffer[i+j] = str[i+j] ^ temp[j];
			}
			if (self->segment_size == BLOCK_SIZE * 8) {
				/* s == b: segment size is identical to 
				   the algorithm block size */
				memcpy(self->IV, buffer + i, BLOCK_SIZE);
			}
			else if ((self->segment_size % 8) == 0) {
				int sz = self->segment_size/8;
				memmove(self->IV, self->IV + sz, 
					BLOCK_SIZE-sz);
				memcpy(self->IV + BLOCK_SIZE - sz, buffer + i,
				       sz);
			}
			else {
				/* segment_size is not a multiple of 8; 
				   currently this can't happen */
			}
		}
		break;

	case(MODE_PGP):
		if (len<=BLOCK_SIZE-self->count) 
		{			
			/* If less than one block, XOR it in */
			for(i=0; i<len; i++) 
				buffer[i] = self->IV[self->count+i] ^= str[i];
			self->count += len;
		}
		else 
		{
			int j;
			for(i=0; i<BLOCK_SIZE-self->count; i++) 
				buffer[i] = self->IV[self->count+i] ^= str[i];
			self->count=0;
			for(; i<len-BLOCK_SIZE; i+=BLOCK_SIZE) 
			{
				block_encrypt(&(self->st), self->oldCipher, 
					      self->IV);
				for(j=0; j<BLOCK_SIZE; j++)
					buffer[i+j] = self->IV[j] ^= str[i+j];
			}
			/* Do the remaining 1 to BLOCK_SIZE bytes */
			block_encrypt(&(self->st), self->oldCipher, self->IV);
			self->count=len-i;
			for(j=0; j<len-i; j++) 
			{
				buffer[i+j] = self->IV[j] ^= str[i+j];
			}
		}
		break;

	case(MODE_OFB):
		for(i=0; i<len; i+=BLOCK_SIZE) 
		{
			block_encrypt(&(self->st), self->IV, temp);
			memcpy(self->IV, temp, BLOCK_SIZE);
			for(j=0; j<BLOCK_SIZE; j++)
			{
				buffer[i+j] = str[i+j] ^ temp[j];
			}
		}      
		break;

	case(MODE_CTR):
		/* CTR mode is a stream cipher whose keystream is generated by encrypting unique counter values.
		 * - self->counter points to the Counter callable, which is
		 *   responsible for generating keystream blocks
		 * - self->count indicates the current offset within the current keystream block
		 * - self->IV stores the current keystream block
		 * - str stores the input string
		 * - buffer stores the output string
		 * - len indicates the length if the input and output strings
		 * - i indicates the current offset within the input and output strings
		 * - (len-i) is the number of bytes remaining to encrypt
		 * - (BLOCK_SIZE-self->count) is the number of bytes remaining in the current keystream block
		 */
		i = 0;
		while (i < len) {
			/* If we don't need more than what remains of the current keystream block, then just XOR it in */
			if (len-i <= BLOCK_SIZE-self->count) { /* remaining_bytes_to_encrypt <= remaining_bytes_in_IV */
				/* XOR until the input is used up */
				for(j=0; j<(len-i); j++) {
					assert(i+j < len);
					assert(self->count+j < BLOCK_SIZE);
					buffer[i+j] = (self->IV[self->count+j] ^= str[i+j]);
				}
				self->count += len-i;
				i = len;
				continue;
			}

			/* Use up the current keystream block */
			for(j=0; j<BLOCK_SIZE-self->count; j++) {
				assert(i+j < len);
				assert(self->count+j < BLOCK_SIZE);
				buffer[i+j] = (self->IV[self->count+j] ^= str[i+j]);
			}
			i += BLOCK_SIZE-self->count;
			self->count = BLOCK_SIZE;

			/* Generate a new keystream block */
			if (self->counter_shortcut) {
				/* CTR mode shortcut: If we're using Util.Counter,
				 * bypass the normal Python function call mechanism
				 * and manipulate the counter directly. */

				PCT_CounterObject *ctr = (PCT_CounterObject *)(self->counter);
				if (ctr->carry && !ctr->allow_wraparound) {
					Py_BLOCK_THREADS;
					PyErr_SetString(PyExc_OverflowError,
							"counter wrapped without allow_wraparound");
					free(buffer);
					return NULL;
				}
				if (ctr->buf_size != BLOCK_SIZE) {
					Py_BLOCK_THREADS;
					PyErr_Format(PyExc_TypeError,
						     "CTR counter function returned "
						     "string not of length %i",
						     BLOCK_SIZE);
					free(buffer);
					return NULL;
				}
				block_encrypt(&(self->st),
					      (unsigned char *)ctr->val,
					      self->IV);
				ctr->inc_func(ctr);
			} else {
				PyObject *ctr;
				Py_BLOCK_THREADS;
				ctr = PyObject_CallObject(self->counter, NULL);
				if (ctr == NULL) {
					free(buffer);
					return NULL;
				}
				if (!PyString_Check(ctr))
				{
					PyErr_SetString(PyExc_TypeError,
							"CTR counter function didn't return a string");
					Py_DECREF(ctr);
					free(buffer);
					return NULL;
				}
				if (PyString_Size(ctr) != BLOCK_SIZE) {
					PyErr_Format(PyExc_TypeError,
						     "CTR counter function returned "
						     "string not of length %i",
						     BLOCK_SIZE);
					Py_DECREF(ctr);
					free(buffer);
					return NULL;
				}
				Py_UNBLOCK_THREADS;
				block_encrypt(&(self->st), (unsigned char *)PyString_AsString(ctr),
					      self->IV);
				Py_BLOCK_THREADS;
				Py_DECREF(ctr);
				Py_UNBLOCK_THREADS;
			}

			/* Move the pointer to the start of the keystream block */
			self->count = 0;
		}
		break;

	default:
		Py_BLOCK_THREADS;
		PyErr_Format(PyExc_SystemError, 
			     "Unknown ciphertext feedback mode %i; "
			     "this shouldn't happen",
			     self->mode);
		free(buffer);
		return NULL;
	}
	Py_END_ALLOW_THREADS;
	result=PyString_FromStringAndSize((char *) buffer, len);
	free(buffer);
	return(result);
}

static char ALG_Decrypt__doc__[] =
"decrypt(string): Decrypt the provided string of binary data.";


static PyObject *
ALG_Decrypt(ALGobject *self, PyObject *args)
{
	unsigned char *buffer, *str;
	unsigned char temp[BLOCK_SIZE];
	int i, j, len;
	PyObject *result;

	/* CTR mode decryption is identical to encryption */
	if (self->mode == MODE_CTR)
		return ALG_Encrypt(self, args);

	if (!PyArg_Parse(args, "s#", &str, &len))
		return NULL;
	if (len==0)			/* Handle empty string */
	{
		return PyString_FromStringAndSize(NULL, 0);
	}
	if ( (len % BLOCK_SIZE) !=0 && 
	     (self->mode!=MODE_CFB && self->mode!=MODE_PGP))
	{
		PyErr_Format(PyExc_ValueError, 
			     "Input strings must be "
			     "a multiple of %i in length",
			     BLOCK_SIZE);
		return NULL;
	}
	if (self->mode == MODE_CFB && 
	    (len % (self->segment_size/8) !=0)) {
		PyErr_Format(PyExc_ValueError, 
			     "Input strings must be a multiple of "
			     "the segment size %i in length",
			     self->segment_size/8);
		return NULL;
	}
	buffer=malloc(len);
	if (buffer==NULL) 
	{
		PyErr_SetString(PyExc_MemoryError, 
				"No memory available in " _MODULE_STRING
				" decrypt");
		return NULL;
	}
	Py_BEGIN_ALLOW_THREADS;
	switch(self->mode)
	{
	case(MODE_ECB):      
		for(i=0; i<len; i+=BLOCK_SIZE) 
		{
			block_decrypt(&(self->st), str+i, buffer+i);
		}
		break;

	case(MODE_CBC):      
		for(i=0; i<len; i+=BLOCK_SIZE) 
		{
			memcpy(self->oldCipher, self->IV, BLOCK_SIZE);
			block_decrypt(&(self->st), str+i, temp);
			for(j=0; j<BLOCK_SIZE; j++) 
			{
				buffer[i+j]=temp[j]^self->IV[j];
				self->IV[j]=str[i+j];
			}
		}
		break;

	case(MODE_CFB):      
		for(i=0; i<len; i+=self->segment_size/8) 
		{
			block_encrypt(&(self->st), self->IV, temp);
			for (j=0; j<self->segment_size/8; j++) {
				buffer[i+j] = str[i+j]^temp[j];
			}
			if (self->segment_size == BLOCK_SIZE * 8) {
				/* s == b: segment size is identical to 
				   the algorithm block size */
				memcpy(self->IV, str + i, BLOCK_SIZE);
			}
			else if ((self->segment_size % 8) == 0) {
				int sz = self->segment_size/8;
				memmove(self->IV, self->IV + sz, 
					BLOCK_SIZE-sz);
				memcpy(self->IV + BLOCK_SIZE - sz, str + i, 
				       sz);
			}
			else {
				/* segment_size is not a multiple of 8; 
				   currently this can't happen */
			}
		}
		break;

	case(MODE_PGP):
		if (len<=BLOCK_SIZE-self->count) 
		{			
                        /* If less than one block, XOR it in */
			unsigned char t;
			for(i=0; i<len; i++)
			{
				t=self->IV[self->count+i];
				buffer[i] = t ^ (self->IV[self->count+i] = str[i]);
			}
			self->count += len;
		}
		else 
		{
			int j;
			unsigned char t;
			for(i=0; i<BLOCK_SIZE-self->count; i++) 
			{
				t=self->IV[self->count+i];
				buffer[i] = t ^ (self->IV[self->count+i] = str[i]);
			}
			self->count=0;
			for(; i<len-BLOCK_SIZE; i+=BLOCK_SIZE) 
			{
				block_encrypt(&(self->st), self->oldCipher, self->IV);
				for(j=0; j<BLOCK_SIZE; j++)
				{
					t=self->IV[j];
					buffer[i+j] = t ^ (self->IV[j] = str[i+j]);
				}
			}
			/* Do the remaining 1 to BLOCK_SIZE bytes */
			block_encrypt(&(self->st), self->oldCipher, self->IV);
			self->count=len-i;
			for(j=0; j<len-i; j++) 
			{
				t=self->IV[j];
				buffer[i+j] = t ^ (self->IV[j] = str[i+j]);
			}
		}
		break;

	case (MODE_OFB):
		for(i=0; i<len; i+=BLOCK_SIZE) 
		{
			block_encrypt(&(self->st), self->IV, temp);
			memcpy(self->IV, temp, BLOCK_SIZE);
			for(j=0; j<BLOCK_SIZE; j++)
			{
				buffer[i+j] = str[i+j] ^ self->IV[j];
			}
		}      
		break;

	default:
		Py_BLOCK_THREADS;
		PyErr_Format(PyExc_SystemError, 
			     "Unknown ciphertext feedback mode %i; "
			     "this shouldn't happen",
			     self->mode);
		free(buffer);
		return NULL;
	}
	Py_END_ALLOW_THREADS;
	result=PyString_FromStringAndSize((char *) buffer, len);
	free(buffer);
	return(result);
}

static char ALG_Sync__doc__[] =
"sync(): For objects using the PGP feedback mode, this method modifies "
"the IV, synchronizing it with the preceding ciphertext.";

static PyObject *
ALG_Sync(ALGobject *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

	if (self->mode!=MODE_PGP) 
	{
		PyErr_SetString(PyExc_SystemError, "sync() operation not defined for "
				"this feedback mode");
		return NULL;
	}
	
	if (self->count!=8) 
	{
		memmove(self->IV+BLOCK_SIZE-self->count, self->IV, 
			self->count);
		memcpy(self->IV, self->oldCipher+self->count, 
		       BLOCK_SIZE-self->count);
		self->count=8;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

#if 0
void PrintState(self, msg)
     ALGobject *self;
     char * msg;
{
  int count;
  
  printf("%sing: %i IV ", msg, (int)self->count);
  for(count=0; count<8; count++) printf("%i ", self->IV[count]);
  printf("\noldCipher:");
  for(count=0; count<8; count++) printf("%i ", self->oldCipher[count]);
  printf("\n");
}
#endif


/* ALG object methods */

static PyMethodDef ALGmethods[] =
{
 {"encrypt", (PyCFunction) ALG_Encrypt, 0, ALG_Encrypt__doc__},
 {"decrypt", (PyCFunction) ALG_Decrypt, 0, ALG_Decrypt__doc__},
 {"sync", (PyCFunction) ALG_Sync, METH_VARARGS, ALG_Sync__doc__},
 {NULL, NULL}			/* sentinel */
};


static int
ALGsetattr(PyObject *ptr, char *name, PyObject *v)
{
  ALGobject *self=(ALGobject *)ptr;
  if (strcmp(name, "IV") != 0) 
    {
      PyErr_Format(PyExc_AttributeError,
		   "non-existent block cipher object attribute '%s'",
		   name);
      return -1;
    }
  if (v==NULL)
    {
      PyErr_SetString(PyExc_AttributeError,
		      "Can't delete IV attribute of block cipher object");
      return -1;
    }
  if (!PyString_Check(v))
    {
      PyErr_SetString(PyExc_TypeError,
		      "IV attribute of block cipher object must be string");
      return -1;
    }
  if (PyString_Size(v)!=BLOCK_SIZE) 
    {
      PyErr_Format(PyExc_ValueError, 
		   _MODULE_STRING " IV must be %i bytes long",
		   BLOCK_SIZE);
      return -1;
    }
  memcpy(self->IV, PyString_AsString(v), BLOCK_SIZE);
  return 0;
}

static PyObject *
ALGgetattr(PyObject *s, char *name)
{
  ALGobject *self = (ALGobject*)s;
  if (strcmp(name, "IV") == 0) 
    {
      return(PyString_FromStringAndSize((char *) self->IV, BLOCK_SIZE));
    }
  if (strcmp(name, "mode") == 0)
     {
       return(PyInt_FromLong((long)(self->mode)));
     }
  if (strcmp(name, "block_size") == 0)
     {
       return PyInt_FromLong(BLOCK_SIZE);
     }
  if (strcmp(name, "key_size") == 0)
     {
       return PyInt_FromLong(KEY_SIZE);
     }
 return Py_FindMethod(ALGmethods, (PyObject *) self, name);
}

/* List of functions defined in the module */

static struct PyMethodDef modulemethods[] =
{
 {"new", (PyCFunction) ALGnew, METH_VARARGS|METH_KEYWORDS, ALGnew__doc__},
 {NULL, NULL}			/* sentinel */
};

static PyTypeObject ALGtype =
{
	PyObject_HEAD_INIT(NULL)
	0,				/*ob_size*/
	_MODULE_STRING,		/*tp_name*/
	sizeof(ALGobject),	/*tp_size*/
	0,				/*tp_itemsize*/
	/* methods */
	ALGdealloc,	/*tp_dealloc*/
	0,				/*tp_print*/
	ALGgetattr,	/*tp_getattr*/
	ALGsetattr,    /*tp_setattr*/
	0,			/*tp_compare*/
	(reprfunc) 0,			/*tp_repr*/
	0,				/*tp_as_number*/
};

/* Initialization function for the module */

#if PYTHON_API_VERSION < 1011
#define PyModule_AddIntConstant(m,n,v) {PyObject *o=PyInt_FromLong(v); \
           if (o!=NULL) \
             {PyDict_SetItemString(PyModule_GetDict(m),n,o); Py_DECREF(o);}}
#endif

void
_MODULE_NAME (void)
{
	PyObject *m;

	ALGtype.ob_type = &PyType_Type;

	/* Create the module and add the functions */
	m = Py_InitModule("Crypto.Cipher." _MODULE_STRING, modulemethods);

	PyModule_AddIntConstant(m, "MODE_ECB", MODE_ECB);
	PyModule_AddIntConstant(m, "MODE_CBC", MODE_CBC);
	PyModule_AddIntConstant(m, "MODE_CFB", MODE_CFB);
	PyModule_AddIntConstant(m, "MODE_PGP", MODE_PGP);
	PyModule_AddIntConstant(m, "MODE_OFB", MODE_OFB);
	PyModule_AddIntConstant(m, "MODE_CTR", MODE_CTR);
	PyModule_AddIntConstant(m, "block_size", BLOCK_SIZE);
	PyModule_AddIntConstant(m, "key_size", KEY_SIZE);

	/* Check for errors */
	if (PyErr_Occurred())
		Py_FatalError("can't initialize module " _MODULE_STRING);
}

/* vim:set ts=8 sw=8 sts=0 noexpandtab: */

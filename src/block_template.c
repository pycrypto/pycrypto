
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

#include "pycrypto_common.h"
#include "modsupport.h"
#include <string.h>
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
#ifdef IS_PY3K
#define _MODULE_NAME _PASTE2(PyInit_,MODULE_NAME)
#else
#define _MODULE_NAME _PASTE2(init,MODULE_NAME)
#endif
#define _MODULE_STRING _XSTR(MODULE_NAME)

/* Object references for the counter_shortcut */
static PyObject *_counter_module = NULL;
static PyTypeObject *PCT_CounterBEType = NULL;
static PyTypeObject *PCT_CounterLEType = NULL;

typedef struct 
{
	PyObject_HEAD 
	int mode, count, segment_size;
	unsigned char IV[BLOCK_SIZE], oldCipher[BLOCK_SIZE];
	PyObject *counter;
	int counter_shortcut;
	block_state st;
} ALGobject;

/* Please see PEP3123 for a discussion of PyObject_HEAD and changes made in 3.x to make it conform to Standard C.
 * These changes also dictate using Py_TYPE to check type, and PyVarObject_HEAD_INIT(NULL, 0) to initialize
 */
staticforward PyTypeObject ALGtype;

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
	block_finalize(&self->st);

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

	if (mode<MODE_ECB || mode>MODE_CTR) 
	{
		PyErr_Format(PyExc_ValueError, 
			     "Unknown cipher feedback mode %i",
			     mode);
		return NULL;
	}
	if (mode == MODE_PGP) {
		PyErr_Format(PyExc_ValueError, 
			     "MODE_PGP is not supported anymore");
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
	if (IVlen != 0 && mode == MODE_ECB)
	{
		PyErr_Format(PyExc_ValueError, "ECB mode does not use IV");
		return NULL;
	}
	if (IVlen != 0 && mode == MODE_CTR)
	{
		PyErr_Format(PyExc_ValueError,
			"CTR mode needs counter parameter, not IV");
		return NULL;
	}
	if (IVlen != BLOCK_SIZE && mode != MODE_ECB && mode != MODE_CTR)
	{
		PyErr_Format(PyExc_ValueError,
			     "IV must be %i bytes long", BLOCK_SIZE);
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
		} else if (Py_TYPE(counter) == PCT_CounterBEType || Py_TYPE(counter) == PCT_CounterLEType) {
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
	new->count=BLOCK_SIZE;   /* stores how many bytes in new->oldCipher have been used */
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
		return PyBytes_FromStringAndSize(NULL, 0);
	}
	if ( (len % BLOCK_SIZE) !=0 && 
	     (self->mode!=MODE_CFB) &&
	     (self->mode!=MODE_OFB) &&
	     (self->mode!=MODE_CTR))
	{
		PyErr_Format(PyExc_ValueError, 
			     "Input strings must be "
			     "a multiple of %i in length",
			     BLOCK_SIZE);
		return NULL;
	}
//	if (self->mode == MODE_CFB &&
//	    (len % (self->segment_size/8) !=0)) {
//		PyErr_Format(PyExc_ValueError,
//			     "Input strings must be a multiple of "
//			     "the segment size %i in length",
//			     self->segment_size/8);
//		return NULL;
//	}

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
	    j = 0;
	    for(i=0; i<len; i++)
	    {
            if (j == 0) {
                block_encrypt(&(self->st), self->IV, temp);
            }

            self->IV[j] = buffer[i] = (unsigned char)( temp[j] ^ str[i] );
            j = ( j + 1 ) & (BLOCK_SIZE - 1);
	    }
		break;

	case(MODE_OFB):
		/* OFB mode is a stream cipher whose keystream is generated by encrypting the previous ciphered output.
		 * - self->IV stores the current keystream block
		 * - self->count indicates the current offset within the current keystream block
		 * - str stores the input string
		 * - buffer stores the output string
		 * - len indicates the length of the input and output strings
		 * - i indicates the current offset within the input and output strings
		 * (len-i) is the number of bytes remaining to encrypt
		 * (BLOCK_SIZE-self->count) is the number of bytes remaining in the current keystream block
		 */
		i = 0;
		while(i < len)
		{
			/* If we don't need more than what remains of the current keystream block, then just XOR it in */
			if (len-i <= BLOCK_SIZE-self->count) { /* remaining_bytes_to_encrypt <= remaining_bytes_in_IV */
				/* XOR until the input is used up */
				for(j=0; j<(len-i); j++) {
					assert(i+j < len);
					assert(self->count+j < BLOCK_SIZE);
					buffer[i+j] = self->IV[self->count+j] ^ str[i+j];
				}
				self->count += len-i;
				i = len;
				continue;
			}

			/* Use up the current keystream block */
			for(j=0; j<BLOCK_SIZE-self->count; j++) {
				assert(i+j < len);
				assert(self->count+j < BLOCK_SIZE);
				buffer[i+j] = self->IV[self->count+j] ^ str[i+j];
			}
			i += BLOCK_SIZE-self->count;
			self->count = BLOCK_SIZE;

			/* Generate a new keystream block */
			block_encrypt(&(self->st), self->IV, temp);
			memcpy(self->IV, temp, BLOCK_SIZE);

			/* Move the pointer to the start of the keystream */
			self->count = 0;
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
						     "string of length %zi, not %i",
						     ctr->buf_size, BLOCK_SIZE);
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
				if (!PyBytes_Check(ctr))
				{
					PyErr_SetString(PyExc_TypeError,
							"CTR counter function didn't return a bytestring");
					Py_DECREF(ctr);
					free(buffer);
					return NULL;
				}
				if (PyBytes_Size(ctr) != BLOCK_SIZE) {
					PyErr_Format(PyExc_TypeError,
						     "CTR counter function returned "
						     "bytestring not of length %i",
						     BLOCK_SIZE);
					Py_DECREF(ctr);
					free(buffer);
					return NULL;
				}
				Py_UNBLOCK_THREADS;
				block_encrypt(&(self->st), (unsigned char *)PyBytes_AsString(ctr),
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
	result=PyBytes_FromStringAndSize((char *) buffer, len);
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
	int i, j, len, c;
	PyObject *result;

	/* CTR and OFB mode decryption is identical to encryption */
	if (self->mode == MODE_CTR || self->mode == MODE_OFB)
		return ALG_Encrypt(self, args);

	if (!PyArg_Parse(args, "s#", &str, &len))
		return NULL;
	if (len==0)			/* Handle empty string */
	{
		return PyBytes_FromStringAndSize(NULL, 0);
	}
	if ( (len % BLOCK_SIZE) !=0 && (self->mode!=MODE_CFB))
	{
		PyErr_Format(PyExc_ValueError, 
			     "Input strings must be "
			     "a multiple of %i in length",
			     BLOCK_SIZE);
		return NULL;
	}
	//if (self->mode == MODE_CFB &&
	//   (len % (self->segment_size/8) !=0)) {
	//	PyErr_Format(PyExc_ValueError,
	//		     "Input strings must be a multiple of "
	//		     "the segment size %i in length",
	//		     self->segment_size/8);
	//	return NULL;
	//}
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
	    j = 0;
	    for(i=0; i<len; i++)
	    {
	        if (j==0) {
	            block_encrypt(&(self->st), self->IV, temp);
	        }
            c = str[i];
            buffer[i] = (unsigned char)(c ^ temp[j]);
            self->IV[j] = (unsigned char)c;

	        j = (j+1)&(BLOCK_SIZE-1);
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
	result=PyBytes_FromStringAndSize((char *) buffer, len);
	free(buffer);
	return(result);
}

/* ALG object methods */
static PyMethodDef ALGmethods[] =
{
 {"encrypt", (PyCFunction) ALG_Encrypt, METH_O, ALG_Encrypt__doc__},
 {"decrypt", (PyCFunction) ALG_Decrypt, METH_O, ALG_Decrypt__doc__},
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
  if (!PyBytes_Check(v))
    {
      PyErr_SetString(PyExc_TypeError,
			  "IV attribute of block cipher object must be bytestring");
      return -1;
    }
  if (PyBytes_Size(v)!=BLOCK_SIZE) 
    {
      PyErr_Format(PyExc_ValueError, 
		   _MODULE_STRING " IV must be %i bytes long",
		   BLOCK_SIZE);
      return -1;
    }
  memcpy(self->IV, PyBytes_AsString(v), BLOCK_SIZE);
  return 0;
}

static PyObject *
ALGgetattro(PyObject *s, PyObject *attr)
{
  ALGobject *self = (ALGobject*)s;

  if (!PyString_Check(attr))
	goto generic;

  if (PyString_CompareWithASCIIString(attr, "IV") == 0)
    {
      return(PyBytes_FromStringAndSize((char *) self->IV, BLOCK_SIZE));
    }
  if (PyString_CompareWithASCIIString(attr, "mode") == 0)
     {
       return(PyInt_FromLong((long)(self->mode)));
     }
  if (PyString_CompareWithASCIIString(attr, "block_size") == 0)
     {
       return PyInt_FromLong(BLOCK_SIZE);
     }
  if (PyString_CompareWithASCIIString(attr, "key_size") == 0)
     {
       return PyInt_FromLong(KEY_SIZE);
     }
  generic:
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	return PyObject_GenericGetAttr(s, attr);
#else
	if (PyString_Check(attr) < 0) {
		PyErr_SetObject(PyExc_AttributeError, attr);
		return NULL;
	}
	return Py_FindMethod(ALGmethods, (PyObject *)self, PyString_AsString(attr));
#endif
}

/* List of functions defined in the module */

static struct PyMethodDef modulemethods[] =
{
 {"new", (PyCFunction) ALGnew, METH_VARARGS|METH_KEYWORDS, ALGnew__doc__},
 {NULL, NULL}			/* sentinel */
};

static PyTypeObject ALGtype =
{
	PyVarObject_HEAD_INIT(NULL, 0)  /* deferred type init for compilation on Windows, type will be filled in at runtime */
	_MODULE_STRING,		/*tp_name*/
	sizeof(ALGobject),	/*tp_size*/
	0,				/*tp_itemsize*/
	/* methods */
	(destructor) ALGdealloc,	/*tp_dealloc*/
	0,				/*tp_print*/
	0,				/*tp_getattr*/
	ALGsetattr,    /*tp_setattr*/
	0,			/*tp_compare*/
	(reprfunc) 0,				/*tp_repr*/
	0,				/*tp_as_number*/
	0,				/*tp_as_sequence */
	0,				/*tp_as_mapping */
	0,				/*tp_hash*/
	0,				/*tp_call*/
	0,				/*tp_str*/
	ALGgetattro,	/*tp_getattro*/
	0,				/*tp_setattro*/
	0,				/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,		/*tp_flags*/
	0,				/*tp_doc*/
	0,				/*tp_traverse*/
	0,				/*tp_clear*/
	0,				/*tp_richcompare*/
	0,				/*tp_weaklistoffset*/
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	0,				/*tp_iter*/
	0,				/*tp_iternext*/
	ALGmethods,		/*tp_methods*/
#endif
};

#ifdef IS_PY3K
static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"Crypto.Cipher." _MODULE_STRING,
	NULL,
	-1,
	modulemethods,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif

/* Initialization function for the module */
PyMODINIT_FUNC
_MODULE_NAME (void)
{
	PyObject *m = NULL;
	PyObject *abiver = NULL;
	PyObject *__all__ = NULL;

	if (PyType_Ready(&ALGtype) < 0)
		goto errout;

	/* Create the module and add the functions */
#ifdef IS_PY3K
	m = PyModule_Create(&moduledef);
#else
	m = Py_InitModule("Crypto.Cipher." _MODULE_STRING, modulemethods);
#endif
	if (m == NULL)
		goto errout;

	/* Add the type object to the module (using the name of the module itself),
	 * so that its methods docstrings are discoverable by introspection tools. */
	PyObject_SetAttrString(m, _MODULE_STRING, (PyObject *)&ALGtype);

	/* Add some symbolic constants to the module */
	PyModule_AddIntConstant(m, "MODE_ECB", MODE_ECB);
	PyModule_AddIntConstant(m, "MODE_CBC", MODE_CBC);
	PyModule_AddIntConstant(m, "MODE_CFB", MODE_CFB);
	PyModule_AddIntConstant(m, "MODE_PGP", MODE_PGP); /** Vestigial **/
	PyModule_AddIntConstant(m, "MODE_OFB", MODE_OFB);
	PyModule_AddIntConstant(m, "MODE_CTR", MODE_CTR);
	PyModule_AddIntConstant(m, "block_size", BLOCK_SIZE);
	PyModule_AddIntConstant(m, "key_size", KEY_SIZE);

	/* Import CounterBE and CounterLE from the _counter module */
	Py_CLEAR(_counter_module);
	_counter_module = PyImport_ImportModule("Crypto.Util._counter");
	if (_counter_module == NULL)
		goto errout;
	PCT_CounterBEType = (PyTypeObject *)PyObject_GetAttrString(_counter_module, "CounterBE");
	PCT_CounterLEType = (PyTypeObject *)PyObject_GetAttrString(_counter_module, "CounterLE");

	/* Simple ABI version check in case the user doesn't re-compile all of
	 * the modules during an upgrade. */
	abiver = PyObject_GetAttrString(_counter_module, "_PCT_CTR_ABI_VERSION");
	if (PCT_CounterBEType == NULL || PyType_Check((PyObject *)PCT_CounterBEType) < 0 ||
		 PCT_CounterLEType == NULL || PyType_Check((PyObject *)PCT_CounterLEType) < 0 ||
		 abiver == NULL || PyInt_CheckExact(abiver) < 0 || PyInt_AS_LONG(abiver) != PCT_CTR_ABI_VERSION)
	{
		PyErr_SetString(PyExc_ImportError, "Crypto.Util._counter ABI mismatch.  Was PyCrypto incorrectly compiled?");
		goto errout;
	}

	/* Create __all__ (to help generate documentation) */
	__all__ = PyList_New(10);
	if (__all__ == NULL)
		goto errout;
	PyList_SetItem(__all__, 0, PyString_FromString(_MODULE_STRING));	/* This is the ALGType object */
	PyList_SetItem(__all__, 1, PyString_FromString("new"));
	PyList_SetItem(__all__, 2, PyString_FromString("MODE_ECB"));
	PyList_SetItem(__all__, 3, PyString_FromString("MODE_CBC"));
	PyList_SetItem(__all__, 4, PyString_FromString("MODE_CFB"));
	PyList_SetItem(__all__, 5, PyString_FromString("MODE_PGP"));
	PyList_SetItem(__all__, 6, PyString_FromString("MODE_OFB"));
	PyList_SetItem(__all__, 7, PyString_FromString("MODE_CTR"));
	PyList_SetItem(__all__, 8, PyString_FromString("block_size"));
	PyList_SetItem(__all__, 9, PyString_FromString("key_size"));
	PyObject_SetAttrString(m, "__all__", __all__);

out:
	/* Final error check */
	if (m == NULL && !PyErr_Occurred()) {
		PyErr_SetString(PyExc_ImportError, "can't initialize module");
		goto errout;
	}

	/* Free local objects here */
	Py_CLEAR(abiver);
	Py_CLEAR(__all__);

	/* Return */
#ifdef IS_PY3K
	return m;
#else
	return;
#endif

errout:
	/* Free the module and other global objects here */
	Py_CLEAR(m);
	Py_CLEAR(_counter_module);
	Py_CLEAR(PCT_CounterBEType);
	Py_CLEAR(PCT_CounterLEType);
	goto out;
}
/* vim:set ts=4 sw=4 sts=0 noexpandtab: */

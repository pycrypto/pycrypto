diff -rauN pycrypto-2.0.1/Cipher/__init__.py pycrypto-2.0.1-batt/Cipher/__init__.py
--- pycrypto-2.0.1/Cipher/__init__.py	2003-02-28 16:28:35.000000000 +0100
+++ pycrypto-2.0.1-batt/Cipher/__init__.py	2007-05-26 13:12:52.000000000 +0200
@@ -20,11 +20,12 @@
 Crypto.Cipher.DES3        Triple DES.
 Crypto.Cipher.IDEA
 Crypto.Cipher.RC5
+Crypto.Cipher.TEA         Tiny Encryption Algorithm
 Crypto.Cipher.XOR         The simple XOR cipher.
 """
 
 __all__ = ['AES', 'ARC2', 'ARC4',
-           'Blowfish', 'CAST', 'DES', 'DES3', 'IDEA', 'RC5',
+           'Blowfish', 'CAST', 'DES', 'DES3', 'IDEA', 'RC5', 'TEA',
            'XOR'
            ]
 
diff -rauN pycrypto-2.0.1/Doc/pycrypt.tex pycrypto-2.0.1-batt/Doc/pycrypt.tex
--- pycrypto-2.0.1/Doc/pycrypt.tex	2005-06-14 02:23:11.000000000 +0200
+++ pycrypto-2.0.1-batt/Doc/pycrypt.tex	2007-05-26 14:37:11.000000000 +0200
@@ -305,6 +305,7 @@
 \lineii{DES3 (Triple DES)}{16 bytes/8 bytes}
 \lineii{IDEA}{16 bytes/8 bytes}
 \lineii{RC5}{Variable/8 bytes}
+\lineii{TEA}{16 bytes/8 bytes}
 \end{tableii}
 
 In a strict formal sense, \dfn{stream ciphers} encrypt data bit-by-bit;
@@ -436,6 +437,12 @@
 balanced between speed and security. 
 \end{itemize}
 
+TEA, Tiny Encrytion Algorithm, is a very fast and easy-to-code algorithm.
+It is famous for its simplicity and efficiency, and is often used in embedded systems,
+where hardware resources (speed and space) are very limited.
+For more information check at: 
+\url{http://www.simonshepherd.supanet.com/tea.htm}
+
 
 \subsection{Security Notes}
 Encryption algorithms can be broken in several ways.  If you have some
diff -rauN pycrypto-2.0.1/setup.py pycrypto-2.0.1-batt/setup.py
--- pycrypto-2.0.1/setup.py	2005-06-14 03:20:22.000000000 +0200
+++ pycrypto-2.0.1-batt/setup.py	2007-05-26 13:29:30.000000000 +0200
@@ -101,6 +101,9 @@
             Extension("Crypto.Cipher.RC5",
                       include_dirs=['src/'],
                       sources=["src/RC5.c"]),
+            Extension("Crypto.Cipher.TEA",
+                      include_dirs=['src/'],
+                      sources=["src/TEA.c"]),
 
             # Stream ciphers
             Extension("Crypto.Cipher.ARC4",
diff -rauN pycrypto-2.0.1/src/TEA.c pycrypto-2.0.1-batt/src/TEA.c
--- pycrypto-2.0.1/src/TEA.c	1970-01-01 01:00:00.000000000 +0100
+++ pycrypto-2.0.1-batt/src/TEA.c	2007-05-26 14:50:52.000000000 +0200
@@ -0,0 +1,137 @@
+/**
+ *
+ * The Tiny Encryption Algorithm (TEA) by David Wheeler and Roger Needham
+ * of the Cambridge Computer Laboratory
+ *
+ * Placed in the Public Domain by David Wheeler and Roger Needham.
+ *
+ * PyCrypto module implementation by Francesco Sacchi <batt@develer.com>
+ *
+ */
+
+#include <stdlib.h>
+#include <string.h>
+#include "Python.h"
+
+#define MODULE_NAME TEA
+#define BLOCK_SIZE 8
+#define KEY_SIZE 16
+
+#define DELTA   0x9E3779B9	//!< Magic value. (Golden number * 2^31)
+#define ROUNDS  32		//!< Number of rounds.
+
+typedef struct {
+	uint32_t k[4];
+} block_state;
+
+
+/**
+ * Macro used to get from a uint8_t *pointer a 32 bit value, little endian.
+ */
+#define GET_LE32(p) (((uint32_t)(p)[3] << 24) \
+                   | ((uint32_t)(p)[2] << 16) \
+                   | ((uint32_t)(p)[1] <<  8) \
+                   | ((uint32_t)(p)[0]))
+
+/**
+ * Macro used to store a 32 bit value in a uint8_t *pointer, little endian.
+ */
+#define STORE_LE32(p, x) { \
+                         (p)[3] = (uint8_t)((x) >> 24); \
+                         (p)[2] = (uint8_t)((x) >> 16); \
+                         (p)[1] = (uint8_t)((x) >>  8); \
+                         (p)[0] = (uint8_t)(x); \
+                       }
+
+
+/**
+ * Basic TEA rotation function.
+ */
+static inline uint32_t tea_func(uint32_t *in, uint32_t *sum, uint32_t *k)
+{
+	return ((*in << 4) + k[0]) ^ (*in + *sum) ^ ((*in >> 5) + k[1]);
+}
+
+/**
+ * \brief TEA encryption function.
+ * This function encrypts <EM>v</EM> with <EM>k</EM> and returns the
+ * encrypted data in <EM>w</EM>.
+ * \param v Array of 8 bytes containing the data block.
+ * \param k Array of four long values containing the key.
+ * \param w Array of 8 bytes containing the encrypted data block.
+ */
+void tea_enc(uint8_t *v, uint32_t *k, uint8_t *w)
+{
+	uint32_t y, z;
+	uint32_t sum = 0;
+	uint8_t n = ROUNDS;
+
+	y = GET_LE32(v);
+	v += 4;
+	z = GET_LE32(v);
+
+	while(n-- > 0)
+	{
+		sum += DELTA;
+		y += tea_func(&z, &sum, &(k[0]));
+		z += tea_func(&y, &sum, &(k[2]));
+	}
+
+	STORE_LE32(w, y);
+	w += 4;
+	STORE_LE32(w, z);
+}
+
+/**
+ * \brief TEA decryption function.
+ * This function decrypts <EM>v</EM> with <EM>k</EM> and returns the
+ * decrypted data in <EM>w</EM>.
+ * \param v Array of 8 bytes containing the data block.
+ * \param k Array of four long values containing the key.
+ * \param w Array of 8 bytes containing the decrypted data block.
+ */
+void tea_dec(uint8_t *v, uint32_t *k, uint8_t *w)
+{
+	uint32_t y, z;
+	uint32_t sum = DELTA * ROUNDS;
+	uint8_t n = ROUNDS;
+
+	y = GET_LE32(v);
+	v += 4;
+	z = GET_LE32(v);
+
+	while(n-- > 0)
+	{
+		z -= tea_func(&y, &sum, &(k[2]));
+		y -= tea_func(&z, &sum, &(k[0]));
+		sum -= DELTA;
+	}
+
+	STORE_LE32(w, y);
+	w += 4;
+	STORE_LE32(w, z);
+}
+
+
+
+void block_init(block_state *self, unsigned char *_key, int dummy)
+{
+	uint8_t *key = (uint8_t *)_key;
+	int i;
+
+	for (i = 0; i < 4; i++)
+		self->k[i] = GET_LE32(key + i * 4);
+}
+
+void block_encrypt(block_state *self, unsigned char *in, unsigned char *out)
+{
+	tea_enc((uint8_t *)in, self->k, (uint8_t *)out);
+}
+
+void block_decrypt(block_state *self, unsigned char *in, unsigned char *out)
+{
+	tea_dec((uint8_t *)in, self->k, (uint8_t *)out);
+}
+
+
+#include "block_template.c"
diff -rauN pycrypto-2.0.1/test/testdata.py pycrypto-2.0.1-batt/test/testdata.py
--- pycrypto-2.0.1/test/testdata.py	2004-08-01 20:53:31.000000000 +0200
+++ pycrypto-2.0.1-batt/test/testdata.py	2007-05-26 14:16:49.000000000 +0200
@@ -423,6 +423,74 @@
         (_castkey[:10*2], _castdata, 'EB6A711A2C02271B'),
         (_castkey[: 5*2], _castdata, '7AC816D16E9B302E'),
         ]
+# Test vector for TEA
+
+tea = [
+('00000000000000000000000000000000','0000000000000000','0a3aea4140a9ba94'),
+('0000000000000000000000000a3aea41','40a9ba9400000000','29788e4ed836827d'),
+('00000000000000000a3aea4129788e4e','d836827d00000000','5ea98bc802acede7'),
+('000000000a3aea4129788e4e5ea98bc8','02acede700000000','af284eb88820b6b6'),
+('0a3aea4129788e4e5ea98bc8af284eb8','8820b6b600000000','9572a4a0b3f3ad8f'),
+('29788e4e5ea98bc8af284eb89572a4a0','b3f3ad8f0a3aea41','980665ed792b9fcf'),
+('5ea98bc8af284eb89572a4a0980665ed','792b9fcf29788e4e','a0ee24101cae2062'),
+('af284eb89572a4a0980665eda0ee2410','1cae20625ea98bc8','d975df5d8fe64c7a'),
+('9572a4a0980665eda0ee2410d975df5d','8fe64c7aaf284eb8','1e9dbef184a9d48d'),
+('980665eda0ee2410d975df5d1e9dbef1','84a9d48d9572a4a0','8c752cd3adab2d09'),
+('a0ee2410d975df5d1e9dbef18c752cd3','adab2d09980665ed','2837b4bdc03f18f7'),
+('d975df5d1e9dbef18c752cd32837b4bd','c03f18f7a0ee2410','1a80c3a94efbdcd9'),
+('1e9dbef18c752cd32837b4bd1a80c3a9','4efbdcd9d975df5d','54e6a1327c91dfa9'),
+('8c752cd32837b4bd1a80c3a954e6a132','7c91dfa91e9dbef1','b93bb608e8d30bb2'),
+('2837b4bd1a80c3a954e6a132b93bb608','e8d30bb28c752cd3','74054121c66442cc'),
+('1a80c3a954e6a132b93bb60874054121','c66442cc2837b4bd','e2d2c54e891dda5a'),
+('54e6a132b93bb60874054121e2d2c54e','891dda5a1a80c3a9','9e2446dd4b0baa28'),
+('b93bb60874054121e2d2c54e9e2446dd','4b0baa2854e6a132','badc862403df13a7'),
+('74054121e2d2c54e9e2446ddbadc8624','03df13a7b93bb608','9dafc7b7ab6ccb1a'),
+('e2d2c54e9e2446ddbadc86249dafc7b7','ab6ccb1a74054121','0a40c08cbb9fa49a'),
+('9e2446ddbadc86249dafc7b70a40c08c','bb9fa49ae2d2c54e','7618249c668cbc6c'),
+('badc86249dafc7b70a40c08c7618249c','668cbc6c9e2446dd','455d9cb5f96600a9'),
+('9dafc7b70a40c08c7618249c455d9cb5','f96600a9badc8624','b3a165b7b07eb364'),
+('0a40c08c7618249c455d9cb5b3a165b7','b07eb3649dafc7b7','ac2f177b3349abf5'),
+('7618249c455d9cb5b3a165b7ac2f177b','3349abf50a40c08c','fbf448feb104a4ad'),
+('455d9cb5b3a165b7ac2f177bfbf448fe','b104a4ad7618249c','934029c53d3ed5c1'),
+('b3a165b7ac2f177bfbf448fe934029c5','3d3ed5c1455d9cb5','e2a89c754966a977'),
+('ac2f177bfbf448fe934029c5e2a89c75','4966a977b3a165b7','0f3ec5690798973e'),
+('fbf448fe934029c5e2a89c750f3ec569','0798973eac2f177b','da8a3860e8a81fa2'),
+('934029c5e2a89c750f3ec569da8a3860','e8a81fa2fbf448fe','f5a170df07a44aac'),
+('e2a89c750f3ec569da8a3860f5a170df','07a44aac934029c5','094ecbd933626392'),
+('0f3ec569da8a3860f5a170df094ecbd9','33626392e2a89c75','576c2c7d4ddb6a7a'),
+('da8a3860f5a170df094ecbd9576c2c7d','4ddb6a7a0f3ec569','1512b7448a3625cf'),
+('f5a170df094ecbd9576c2c7d1512b744','8a3625cfda8a3860','a10501c1181a78ef'),
+('094ecbd9576c2c7d1512b744a10501c1','181a78eff5a170df','fa29dbbfb639ce9e'),
+('576c2c7d1512b744a10501c1fa29dbbf','b639ce9e094ecbd9','6d250b9b4c5704dc'),
+('1512b744a10501c1fa29dbbf6d250b9b','4c5704dc576c2c7d','425129f81127028c'),
+('a10501c1fa29dbbf6d250b9b425129f8','1127028c1512b744','1c1d3461f0f2853a'),
+('fa29dbbf6d250b9b425129f81c1d3461','f0f2853aa10501c1','0cd3a0f6090223ad'),
+('6d250b9b425129f81c1d34610cd3a0f6','090223adfa29dbbf','3f1ae23dc9f50caa'),
+('425129f81c1d34610cd3a0f63f1ae23d','c9f50caa6d250b9b','c607e3a739d952bd'),
+('1c1d34610cd3a0f63f1ae23dc607e3a7','39d952bd425129f8','a7c37b01778cfd66'),
+('0cd3a0f63f1ae23dc607e3a7a7c37b01','778cfd661c1d3461','86fcf8d861571bd0'),
+('3f1ae23dc607e3a7a7c37b0186fcf8d8','61571bd00cd3a0f6','1ac486e14d5a6e5e'),
+('c607e3a7a7c37b0186fcf8d81ac486e1','4d5a6e5e3f1ae23d','24d2684377e6b4db'),
+('a7c37b0186fcf8d81ac486e124d26843','77e6b4dbc607e3a7','1e32d09b23650984'),
+('86fcf8d81ac486e124d268431e32d09b','23650984a7c37b01','5b6dc5b76658c697'),
+('1ac486e124d268431e32d09b5b6dc5b7','6658c69786fcf8d8','acbfa163a27c5d5a'),
+('24d268431e32d09b5b6dc5b7acbfa163','a27c5d5a1ac486e1','ff6df5914f798172'),
+('1e32d09b5b6dc5b7acbfa163ff6df591','4f79817224d26843','8037c6e4f7ed9a01'),
+('5b6dc5b7acbfa163ff6df5918037c6e4','f7ed9a011e32d09b','e756fba9caaef435'),
+('acbfa163ff6df5918037c6e4e756fba9','caaef4355b6dc5b7','877153a693baf1f0'),
+('ff6df5918037c6e4e756fba9877153a6','93baf1f0acbfa163','da0e96cc8f6b4ce4'),
+('8037c6e4e756fba9877153a6da0e96cc','8f6b4ce4ff6df591','6d102fe1d052114f'),
+('e756fba9877153a6da0e96cc6d102fe1','d052114f8037c6e4','53d86a55fd9299f7'),
+('877153a6da0e96cc6d102fe153d86a55','fd9299f7e756fba9','65e2e878adf68d12'),
+('da0e96cc6d102fe153d86a5565e2e878','adf68d12877153a6','aa9238f226b98c28'),
+('6d102fe153d86a5565e2e878aa9238f2','26b98c28da0e96cc','3958111dca7f116a'),
+('53d86a5565e2e878aa9238f23958111d','ca7f116a6d102fe1','359689cf347e085b'),
+('65e2e878aa9238f23958111d359689cf','347e085b53d86a55','f2bf605cc2888de6'),
+('aa9238f23958111d359689cff2bf605c','c2888de665e2e878','1cd072700ab5febf'),
+('3958111d359689cff2bf605c1cd07270','0ab5febfaa9238f2','ebc513459eae999c'),
+('359689cff2bf605c1cd07270ebc51345','9eae999c3958111d','ab383a8fadc4d980'),
+('f2bf605c1cd07270ebc51345ab383a8f','adc4d980359689cf','b3f1b02b11ed23c0')
+]
 
 # Test data for XOR
 
diff -rauN pycrypto-2.0.1/Util/test.py pycrypto-2.0.1-batt/Util/test.py
--- pycrypto-2.0.1/Util/test.py	2004-08-14 00:24:18.000000000 +0200
+++ pycrypto-2.0.1-batt/Util/test.py	2007-05-26 13:25:08.000000000 +0200
@@ -224,7 +224,7 @@
 
 
 def TestBlockModules(args=['aes', 'arc2', 'des', 'blowfish', 'cast', 'des3',
-                           'idea', 'rc5'],
+                           'idea', 'rc5', 'tea'],
                      verbose=1):
     import string
     args=map(string.lower, args)
@@ -449,5 +449,20 @@
                             if verbose: print hex(ord(i)),
                         if verbose: print
 
+    if 'tea' in args:
+        ciph=exerciseBlockCipher('TEA', verbose)       # TEA block cipher
+        if (ciph!=None):
+                if verbose: print '  Verifying against test suite...'
+                for entry in testdata.tea:
+                    key,plain,cipher=entry
+                    key=binascii.a2b_hex(key)
+                    plain=binascii.a2b_hex(plain)
+                    cipher=binascii.a2b_hex(cipher)
+                    obj=ciph.new(key, ciph.MODE_ECB)
+                    ciphertext=obj.encrypt(plain)
+                    if (ciphertext!=cipher):
+                        die('TEA failed on entry '+`entry`)
+
+
 
 


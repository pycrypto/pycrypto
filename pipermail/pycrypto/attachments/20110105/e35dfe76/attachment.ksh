diff --git a/lib/Crypto/Random/random.py b/lib/Crypto/Random/random.py
index 9d969f2..c5fdb70 100644
--- a/lib/Crypto/Random/random.py
+++ b/lib/Crypto/Random/random.py
@@ -119,13 +119,11 @@ class StrongRandom(object):
             raise ValueError("sample larger than population")
 
         retval = []
-        selected = {}  # we emulate a set using a dict here
         for i in xrange(k):
-            r = None
-            while r is None or r in selected:
+            r = self.randrange(num_choices)
+            while population[r] in retval:
                 r = self.randrange(num_choices)
             retval.append(population[r])
-            selected[r] = 1
         return retval
 
 _r = StrongRandom()

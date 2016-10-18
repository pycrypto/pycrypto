/*
 * added to provide rpl_malloc() when GNU MALLOC
 * RATHER than as a AC_LIBOBJ replacement
 * Note also: rpl_malloc, not being previously defined
 * and without prototype was being seen as a function
 * that returns an int rather than as unsigned char *
 */
#ifdef HAVE_MALLOC
#if HAVE_MALLOC == 0
#undef malloc
#include <malloc.h>
#ifdef _AIX
#include <sys/malloc.h>
#endif

     /*
      * Allocate an N-byte block of memory from the heap.
      * If N is zero, allocate a 1-byte block.
      * static because block_template.c may be included several times
      */

     static void *
     rpl_malloc (size_t n)
     {
       if (n == 0)
         n = 1;
       return (void *) malloc (n);
     }
/*
 * restore definition of malloc to rpl_malloc for code below
 */
#define malloc rpl_malloc
#endif
#endif


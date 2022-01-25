/* Public domain. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFSIZE (1024*1024*1024)    /* 1 GiB */

int main(int argc, char **argv)
{
    FILE *file;
    int err;
    size_t count;
    char *buf;
    char *filename;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s FILE\n", argv[0]);
        fprintf(stderr, "Read from FILE\n");
        return 1;
    }
    filename = argv[1];

    /* Allocate buffer */
    buf = malloc(BUFSIZE);
    if (buf == NULL) {
        perror("malloc() failed");
        exit(1);
    }

    /* Open device */
    file = fopen(filename, "rb");
    if (file == NULL) {
        perror("fopen() error");
        exit(1);
    }
    printf("fopen() successful.\n");

    /* Perform reads */
    do {
        count = fread(buf, 1, BUFSIZE, file);
        if (count == BUFSIZE) {
            printf("OK: count: 0x%08x\n", count);
        } else {
            printf("ERROR: count: 0x%08x\n", count);
        }
    } while (count != 0);
    printf("EOF detected\n");

    /* Close the file */
    err = fclose(file);
    if (err == EOF) {
        perror("fclose() failed");
        exit(1);
    }

    /* Free memory */
    free(buf);
    return 0;
}

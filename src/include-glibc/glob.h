# define GLOB_TILDE  (1 << 12)/* Expand ~user and ~ to home directories. */

typedef struct
  {
    int gl_pathc;		/* Count of paths matched by the pattern.  */
    char **gl_pathv;		/* List of matched pathnames.  */
    int gl_offs;		/* Slots to reserve in `gl_pathv'.  */
    int gl_flags;		/* Set to FLAGS, maybe | GLOB_MAGCHAR.  */

    /* If the GLOB_ALTDIRFUNC flag is set, the following functions
       are used instead of the normal file access functions.  */
    void (*gl_closedir) (void *);
    void *(*gl_readdir) (void *);
    void *(*gl_opendir) (__const char *);
    int (*gl_lstat) (__const char *__restrict, void *__restrict);
    int (*gl_stat) (__const char *__restrict, void *__restrict);
  } glob_t;

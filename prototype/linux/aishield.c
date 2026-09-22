#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

#define MAX_ROOTS 128

static const unsigned long long read_rights =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR;
static const unsigned long long write_rights =
    LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;

struct root { char *path; bool write; };

static void die(const char *message) {
    perror(message);
    exit(1);
}

static bool contains(const char *parent, const char *child) {
    size_t n = strlen(parent);
    return strcmp(parent, child) == 0 ||
           (strncmp(parent, child, n) == 0 &&
            (parent[n - 1] == '/' || child[n] == '/'));
}

static void usage(void) {
    fprintf(stderr, "usage: aishield-proto [--read PATH] [--write PATH] [--lock PATH] -- COMMAND [ARGS...]\n");
    exit(2);
}

int main(int argc, char **argv) {
    struct root roots[MAX_ROOTS];
    char *locks[MAX_ROOTS];
    size_t root_count = 0, lock_count = 0;
    int i = 1;
    while (i < argc && strcmp(argv[i], "--") != 0) {
        if (i + 1 >= argc) usage();
        bool rd = strcmp(argv[i], "--read") == 0;
        bool wr = strcmp(argv[i], "--write") == 0;
        bool lk = strcmp(argv[i], "--lock") == 0;
        if (!rd && !wr && !lk) usage();
        char *path = realpath(argv[i + 1], NULL);
        if (!path) die("realpath");
        if (lk) {
            if (lock_count == MAX_ROOTS) usage();
            locks[lock_count++] = path;
        } else {
            if (root_count == MAX_ROOTS) usage();
            roots[root_count++] = (struct root){path, wr};
        }
        i += 2;
    }
    if (i >= argc - 1 || root_count == 0) usage();
    for (size_t r = 0; r < root_count; r++) {
        for (size_t l = 0; l < lock_count; l++) {
            if (contains(roots[r].path, locks[l])) {
                fprintf(stderr, "grant %s contains locked path %s; grant narrower roots\n",
                        roots[r].path, locks[l]);
                return 1;
            }
        }
    }

    int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) die("Landlock unavailable");
    struct landlock_ruleset_attr ruleset = {0};
    ruleset.handled_access_fs = read_rights | write_rights;
    if (abi >= 2) ruleset.handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) ruleset.handled_access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) ruleset.handled_access_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    int ruleset_fd = (int)syscall(SYS_landlock_create_ruleset, &ruleset,
                                  sizeof(ruleset), 0);
    if (ruleset_fd < 0) die("create Landlock ruleset");

    for (size_t r = 0; r < root_count; r++) {
        int fd = open(roots[r].path, O_PATH | O_CLOEXEC);
        if (fd < 0) die("open grant root");
        struct landlock_path_beneath_attr rule = {
            .allowed_access = read_rights | (roots[r].write ? write_rights : 0),
            .parent_fd = fd,
        };
        if (abi >= 2 && roots[r].write) rule.allowed_access |= LANDLOCK_ACCESS_FS_REFER;
        if (abi >= 3 && roots[r].write) rule.allowed_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
        if (abi >= 5 && roots[r].write) rule.allowed_access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        if (syscall(SYS_landlock_add_rule, ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH, &rule, 0) < 0)
            die("add Landlock rule");
        close(fd);
    }

    /* Close pre-sandbox handles. The ruleset itself is not needed after installation. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die("no_new_privs");
    if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0)
        die("restrict self");
    close(ruleset_fd);
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 1048576) maxfd = 1048576;
    for (long fd = 3; fd < maxfd; fd++) close((int)fd);
    execvp(argv[i + 1], &argv[i + 1]);
    die("exec command");
}

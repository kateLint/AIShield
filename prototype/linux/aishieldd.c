#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define POLICY_DIR "/etc/aishield"
#define SOCKET_DIR "/run/aishield"
#define SOCKET_PATH SOCKET_DIR "/control.sock"
#define MAX_LOCKS 128

static volatile sig_atomic_t stopping;

static void fail(const char *what) { perror(what); exit(1); }

static void on_signal(int signal_number) { (void)signal_number; stopping = 1; }

static void write_all(int fd, const char *text) {
    size_t left = strlen(text);
    while (left) {
        ssize_t n = write(fd, text, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return;
        text += n;
        left -= (size_t)n;
    }
}

static void require_root_owned(int fd, bool directory) {
    struct stat st;
    if (fstat(fd, &st) < 0) fail("stat policy");
    if (st.st_uid != 0 || (st.st_mode & 022) ||
        (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))) {
        fprintf(stderr, "policy location must be root-owned and not group/other writable\n");
        exit(1);
    }
}

static int open_policy_dir(void) {
    if (mkdir(POLICY_DIR, 0755) < 0 && errno != EEXIST) fail("create policy dir");
    int fd = open(POLICY_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) fail("open policy dir");
    require_root_owned(fd, true);
    if (fchmod(fd, 0755) < 0) fail("chmod policy dir");
    return fd;
}

static size_t load_locks(int dirfd, char **locks) {
    int fd = openat(dirfd, "locks", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return 0;
        fail("open locks");
    }
    require_root_owned(fd, false);
    FILE *stream = fdopen(fd, "r");
    if (!stream) fail("fdopen locks");
    size_t count = 0;
    char line[PATH_MAX + 2];
    while (fgets(line, sizeof(line), stream)) {
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n') line[--len] = '\0';
        else if (!feof(stream)) { fprintf(stderr, "lock path too long\n"); exit(1); }
        if (!len || line[0] == '#') continue;
        if (line[0] != '/' || count == MAX_LOCKS) {
            fprintf(stderr, "invalid lock entry\n"); exit(1);
        }
        char *resolved = realpath(line, NULL);
        if (!resolved) fail("resolve lock entry");
        locks[count++] = resolved;
    }
    if (ferror(stream)) fail("read locks");
    fclose(stream);
    return count;
}

static void save_locks(int dirfd, char **locks, size_t count) {
    char name[] = ".locks.XXXXXX";
    char path[sizeof(POLICY_DIR) + sizeof(name) + 1];
    snprintf(path, sizeof(path), "%s/%s", POLICY_DIR, name);
    int fd = mkstemp(path);
    if (fd < 0) fail("create temporary locks");
    if (fchmod(fd, 0644) < 0) fail("chmod temporary locks");
    for (size_t i = 0; i < count; i++) {
        if (write(fd, locks[i], strlen(locks[i])) != (ssize_t)strlen(locks[i]) ||
            write(fd, "\n", 1) != 1) fail("write temporary locks");
    }
    if (fsync(fd) < 0) fail("sync temporary locks");
    if (close(fd) < 0) fail("close temporary locks");
    const char *base = strrchr(path, '/') + 1;
    if (renameat(dirfd, base, dirfd, "locks") < 0) fail("replace locks");
    if (fsync(dirfd) < 0) fail("sync policy dir");
}

static void handle_client(int client, int dirfd) {
    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) < 0 ||
        peer_len != sizeof(peer) || peer.uid != 0) {
        write_all(client, "ERROR root authorization required\n");
        return;
    }
    char request[PATH_MAX + 32];
    ssize_t n = read(client, request, sizeof(request) - 1);
    if (n <= 0) return;
    request[n] = '\0';
    char *end = strchr(request, '\n');
    if (!end || end[1] != '\0') {
        write_all(client, "ERROR one newline-terminated command required\n");
        return;
    }
    *end = '\0';
    char *locks[MAX_LOCKS];
    size_t count = load_locks(dirfd, locks);
    if (strcmp(request, "STATUS") == 0) {
        write_all(client, "OK locks\n");
        for (size_t i = 0; i < count; i++) {
            write_all(client, locks[i]);
            write_all(client, "\n");
        }
    } else {
        bool add = strncmp(request, "LOCK ", 5) == 0;
        bool remove = strncmp(request, "UNLOCK ", 7) == 0;
        if (!add && !remove) {
            write_all(client, "ERROR unknown command\n");
        } else {
            const char *input = request + (add ? 5 : 7);
            char *path = realpath(input, NULL);
            if (!path) {
                write_all(client, "ERROR path must exist\n");
            } else {
                bool consumed = false;
                size_t pos = 0;
                while (pos < count && strcmp(locks[pos], path) != 0) pos++;
                if (add && pos == count && count == MAX_LOCKS) {
                    write_all(client, "ERROR too many locks\n");
                } else if (remove && pos == count) {
                    write_all(client, "ERROR path is not locked\n");
                } else {
                    bool changed = remove || (add && pos == count);
                    if (add && pos == count) { locks[count++] = path; consumed = true; }
                    if (remove) {
                        free(locks[pos]);
                        for (size_t j = pos + 1; j < count; j++) locks[j - 1] = locks[j];
                        count--;
                    }
                    if (changed) save_locks(dirfd, locks, count);
                    write_all(client, changed ? "OK policy updated; restart affected agents\n"
                                              : "OK already locked\n");
                }
                if (!consumed) free(path);
            }
        }
    }
    for (size_t i = 0; i < count; i++) free(locks[i]);
}

int main(void) {
    if (geteuid() != 0) { fprintf(stderr, "aishieldd must run as root\n"); return 1; }
    umask(077);
    int dirfd = open_policy_dir();
    if (mkdir(SOCKET_DIR, 0700) < 0 && errno != EEXIST) fail("create socket dir");
    int socket_dir = open(SOCKET_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (socket_dir < 0) fail("open socket dir");
    require_root_owned(socket_dir, true);
    close(socket_dir);
    if (access(SOCKET_PATH, F_OK) == 0) {
        fprintf(stderr, "control socket already exists; refusing to replace it\n"); return 1;
    }
    int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0) fail("create socket");
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", SOCKET_PATH);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) < 0) fail("bind socket");
    if (chmod(SOCKET_PATH, 0600) < 0 || listen(server, 8) < 0) fail("listen socket");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) fail("no_new_privs");
    struct sigaction action = {.sa_handler = on_signal};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) < 0 ||
        sigaction(SIGINT, &action, NULL) < 0) fail("install signal handler");
    signal(SIGPIPE, SIG_IGN);
    while (!stopping) {
        int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR) continue;
            fail("accept client");
        }
        handle_client(client, dirfd);
        close(client);
    }
    close(server);
    unlink(SOCKET_PATH);
    close(dirfd);
    return 0;
}

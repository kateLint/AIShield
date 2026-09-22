#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/run/aishield/control.sock"

int main(int argc, char **argv) {
    const char *verb;
    if (argc == 2 && strcmp(argv[1], "status") == 0) verb = "STATUS";
    else if (argc == 3 && strcmp(argv[1], "lock") == 0) verb = "LOCK";
    else if (argc == 3 && strcmp(argv[1], "unlock") == 0) verb = "UNLOCK";
    else {
        fprintf(stderr, "usage: aishieldctl status | lock PATH | unlock PATH\n");
        return 2;
    }
    if (argc == 3 && (strchr(argv[2], '\n') || strlen(argv[2]) > 4096)) {
        fprintf(stderr, "invalid path\n"); return 2;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", SOCKET_PATH);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("connect AIShield control service"); return 1;
    }
    char request[4120];
    int n = snprintf(request, sizeof(request), argc == 3 ? "%s %s\n" : "%s\n",
                     verb, argc == 3 ? argv[2] : "");
    if (n < 0 || n >= (int)sizeof(request) || write(fd, request, (size_t)n) != n) {
        perror("send request"); return 1;
    }
    if (shutdown(fd, SHUT_WR) < 0) { perror("shutdown"); return 1; }
    FILE *stream = fdopen(fd, "r");
    if (!stream) { perror("read response"); return 1; }
    char response[4096];
    if (!fgets(response, sizeof(response), stream)) {
        fprintf(stderr, "empty service response\n"); return 1;
    }
    bool error = strncmp(response, "ERROR", 5) == 0;
    fputs(response, error ? stderr : stdout);
    while (fgets(response, sizeof(response), stream))
        fputs(response, error ? stderr : stdout);
    if (ferror(stream)) { perror("read response"); return 1; }
    fclose(stream);
    return error ? 1 : 0;
}

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/landlock.h>
#include <poll.h>
#include <seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#elif defined(__aarch64__)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#else
#error "Landlock syscall numbers are unavailable for this architecture"
#endif
#endif

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

#define MAX_RULES 64
#define MAX_CONSTRAINTS 128
#define MAX_PATHS 64
#define MAX_PORTS 64
#define MAX_TEXT 256
#define MAX_CGROUP 4096
#define DEFAULT_DEADLINE_MS 5000

enum direct_kind { DIRECT_ALLOW, DIRECT_ERRNO, DIRECT_KILL };
enum decision_kind { DECISION_ALLOW, DECISION_DENY, DECISION_EMULATE };

struct direct_rule {
    enum direct_kind kind;
    int syscall_nr;
    int error_number;
    char syscall_name[64];
};

struct argument_constraint {
    int syscall_nr;
    unsigned int index;
    uint64_t value;
};

struct notify_rule {
    int syscall_nr;
    enum decision_kind decision;
    int error_number;
    int64_t value;
    char syscall_name[64];
};

struct path_rule {
    char path[4096];
    bool writable;
};

struct port_rule {
    uint64_t port;
    bool bind;
};

struct profile {
    uint32_t default_action;
    struct direct_rule direct_rules[MAX_RULES];
    size_t direct_count;
    struct notify_rule notify_rules[MAX_RULES];
    size_t notify_count;
    struct argument_constraint constraints[MAX_CONSTRAINTS];
    size_t constraint_count;
    struct path_rule paths[MAX_PATHS];
    size_t path_count;
    struct port_rule ports[MAX_PORTS];
    size_t port_count;
    int deadline_ms;
    char transaction_id[MAX_TEXT];
};

struct process_identity {
    pid_t pid;
    unsigned long long start_time;
    char cgroup[MAX_CGROUP];
};

static void fail(const char *message) {
    fprintf(stderr, "{\"ok\":false,\"error\":\"%s\",\"errno\":%d}\n", message, errno);
    exit(1);
}

static bool safe_identifier(const char *value) {
    if (value == NULL || value[0] == '\0' || strlen(value) >= MAX_TEXT) return false;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' || *p == ':' || *p == '-' )) return false;
    }
    return true;
}

static long long monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000LL;
}

static int resolve_syscall(const char *name) {
    int number = seccomp_syscall_resolve_name(name);
    if (number == __NR_SCMP_ERROR) {
        errno = EINVAL;
        fail("unknown_syscall");
    }
    return number;
}

static uint64_t parse_u64(const char *value, const char *label) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 0);
    if (errno != 0 || end == value || *end != '\0') {
        errno = EINVAL;
        fail(label);
    }
    return (uint64_t)parsed;
}

static int parse_positive_int(const char *value, const char *label, int maximum) {
    uint64_t parsed = parse_u64(value, label);
    if (parsed < 1 || parsed > (uint64_t)maximum) {
        errno = EINVAL;
        fail(label);
    }
    return (int)parsed;
}

static void split3(const char *input, char *first, size_t first_size, char *second, size_t second_size, char *third, size_t third_size) {
    const char *a = strchr(input, ':');
    if (a == NULL) { errno = EINVAL; fail("invalid_rule"); }
    const char *b = strchr(a + 1, ':');
    size_t first_length = (size_t)(a - input);
    size_t second_length = b == NULL ? strlen(a + 1) : (size_t)(b - (a + 1));
    if (first_length == 0 || first_length >= first_size || second_length == 0 || second_length >= second_size) { errno = EINVAL; fail("invalid_rule"); }
    memcpy(first, input, first_length); first[first_length] = '\0';
    memcpy(second, a + 1, second_length); second[second_length] = '\0';
    if (b == NULL) third[0] = '\0';
    else {
        size_t third_length = strlen(b + 1);
        if (third_length == 0 || third_length >= third_size) { errno = EINVAL; fail("invalid_rule"); }
        memcpy(third, b + 1, third_length + 1);
    }
}

static int landlock_abi(void) {
    int result = (int)syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    return result < 0 ? -errno : result;
}

static uint64_t landlock_fs_rights(int abi) {
    uint64_t rights = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2) rights |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
    return rights;
}

static int apply_landlock(const struct profile *profile, int *abi_out) {
    if (profile->path_count == 0 && profile->port_count == 0) {
        if (abi_out != NULL) *abi_out = landlock_abi();
        return 0;
    }
    int abi = landlock_abi();
    if (abi_out != NULL) *abi_out = abi;
    if (abi < 1) return abi == 0 ? -ENOSYS : abi;
    struct landlock_ruleset_attr ruleset = {0};
    ruleset.handled_access_fs = profile->path_count > 0 ? landlock_fs_rights(abi) : 0;
    if (profile->port_count > 0) {
        if (abi < 4) return -EOPNOTSUPP;
        ruleset.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    }
    size_t ruleset_size = abi >= 4 ? sizeof(ruleset) : offsetof(struct landlock_ruleset_attr, handled_access_net);
    int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &ruleset, ruleset_size, 0);
    if (ruleset_fd < 0) return -errno;
    uint64_t all_fs = landlock_fs_rights(abi);
    for (size_t i = 0; i < profile->path_count; ++i) {
        int parent_fd = open(profile->paths[i].path, O_PATH | O_CLOEXEC);
        if (parent_fd < 0) { int error = -errno; close(ruleset_fd); return error; }
        struct landlock_path_beneath_attr path = {
            .allowed_access = profile->paths[i].writable ? all_fs : (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR),
            .parent_fd = parent_fd,
        };
        int result = (int)syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path, 0);
        int error = result < 0 ? -errno : 0;
        close(parent_fd);
        if (error != 0) { close(ruleset_fd); return error; }
    }
    for (size_t i = 0; i < profile->port_count; ++i) {
        struct landlock_net_port_attr port = {
            .allowed_access = profile->ports[i].bind ? LANDLOCK_ACCESS_NET_BIND_TCP : LANDLOCK_ACCESS_NET_CONNECT_TCP,
            .port = profile->ports[i].port,
        };
        int result = (int)syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_NET_PORT, &port, 0);
        if (result < 0) { int error = -errno; close(ruleset_fd); return error; }
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { int error = -errno; close(ruleset_fd); return error; }
    int result = (int)syscall(__NR_landlock_restrict_self, ruleset_fd, 0);
    int error = result < 0 ? -errno : 0;
    close(ruleset_fd);
    return error;
}

static int send_fd(int socket_fd, int fd) {
    char marker = 'F';
    struct iovec iov = { .iov_base = &marker, .iov_len = 1 };
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct msghdr message = {0};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(int));
    message.msg_controllen = header->cmsg_len;
    return sendmsg(socket_fd, &message, 0) == 1 ? 0 : -1;
}

static int receive_fd(int socket_fd) {
    char marker = 0;
    struct iovec iov = { .iov_base = &marker, .iov_len = 1 };
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct msghdr message = {0};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    if (recvmsg(socket_fd, &message, 0) != 1) return -1;
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (header == NULL || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS || header->cmsg_len < CMSG_LEN(sizeof(int))) return -1;
    int fd = -1;
    memcpy(&fd, CMSG_DATA(header), sizeof(int));
    return fd;
}

static int read_process_identity(pid_t pid, struct process_identity *identity) {
    char path[128];
    char data[8192];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t length = read(fd, data, sizeof(data) - 1);
    close(fd);
    if (length <= 0) return -EIO;
    data[length] = '\0';
    char *right = strrchr(data, ')');
    if (right == NULL || right[1] != ' ') return -EINVAL;
    char *save = NULL;
    char *token = strtok_r(right + 2, " ", &save);
    int field = 3;
    unsigned long long start = 0;
    while (token != NULL) {
        if (field == 22) { start = strtoull(token, NULL, 10); break; }
        field += 1;
        token = strtok_r(NULL, " ", &save);
    }
    if (start == 0) return -EINVAL;
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    length = read(fd, identity->cgroup, sizeof(identity->cgroup) - 1);
    close(fd);
    if (length < 0) return -errno;
    identity->cgroup[length] = '\0';
    identity->pid = pid;
    identity->start_time = start;
    return 0;
}

static bool same_identity(const struct process_identity *expected, pid_t observed_pid, bool force_conflict) {
    if (force_conflict || observed_pid != expected->pid) return false;
    struct process_identity actual = {0};
    if (read_process_identity(observed_pid, &actual) != 0) return false;
    return actual.start_time == expected->start_time && strcmp(actual.cgroup, expected->cgroup) == 0;
}

static const struct notify_rule *find_notify_rule(const struct profile *profile, int syscall_nr) {
    for (size_t i = 0; i < profile->notify_count; ++i) if (profile->notify_rules[i].syscall_nr == syscall_nr) return &profile->notify_rules[i];
    return NULL;
}

static bool arguments_match(const struct profile *profile, const struct seccomp_notif *request) {
    for (size_t i = 0; i < profile->constraint_count; ++i) {
        const struct argument_constraint *constraint = &profile->constraints[i];
        if (constraint->syscall_nr == request->data.nr && request->data.args[constraint->index] != constraint->value) return false;
    }
    return true;
}

static int install_seccomp(const struct profile *profile, scmp_filter_ctx *context_out) {
    scmp_filter_ctx context = seccomp_init(profile->default_action);
    if (context == NULL) return -ENOMEM;
    if (seccomp_attr_set(context, SCMP_FLTATR_CTL_NNP, 1) != 0) { seccomp_release(context); return -EINVAL; }
    for (size_t i = 0; i < profile->direct_count; ++i) {
        const struct direct_rule *rule = &profile->direct_rules[i];
        uint32_t action = rule->kind == DIRECT_ALLOW ? SCMP_ACT_ALLOW : rule->kind == DIRECT_KILL ? SCMP_ACT_KILL_PROCESS : SCMP_ACT_ERRNO(rule->error_number);
        if (action == profile->default_action) continue;
        int result = seccomp_rule_add(context, action, rule->syscall_nr, 0);
        if (result != 0) { seccomp_release(context); return result; }
    }
    for (size_t i = 0; i < profile->notify_count; ++i) {
        int result = seccomp_rule_add(context, SCMP_ACT_NOTIFY, profile->notify_rules[i].syscall_nr, 0);
        if (result != 0) { seccomp_release(context); return result; }
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { int error = -errno; seccomp_release(context); return error; }
    int result = seccomp_load(context);
    if (result != 0) { seccomp_release(context); return result; }
    *context_out = context;
    return 0;
}

static int child_status_code(int status) {
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 255;
}

static int supervise(const struct profile *profile, char *const command[], const char *test_mode, bool force_identity_conflict, bool supervisor_death, bool stale_check, int *event_count_out) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) return -errno;
    pid_t child = fork();
    if (child < 0) { int error = -errno; close(sockets[0]); close(sockets[1]); return error; }
    if (child == 0) {
        close(sockets[0]);
        int abi = 0;
        int landlock_result = apply_landlock(profile, &abi);
        if (landlock_result != 0) _exit(120);
        scmp_filter_ctx context = NULL;
        int filter_result = install_seccomp(profile, &context);
        if (filter_result != 0) _exit(121);
        int listener = profile->notify_count > 0 ? seccomp_notify_fd(context) : -1;
        if (profile->notify_count > 0) {
            if (listener < 0 || send_fd(sockets[1], listener) != 0) _exit(122);
            close(listener);
        } else {
            char ready = 'R';
            if (write(sockets[1], &ready, 1) != 1) _exit(123);
        }
        seccomp_release(context);
        char go = 0;
        if (read(sockets[1], &go, 1) != 1) _exit(124);
        close(sockets[1]);
        if (test_mode != NULL) {
            errno = 0;
            long result = syscall(SYS_getpid);
            int ok = 0;
            if (strcmp(test_mode, "allow") == 0 || strcmp(test_mode, "stale") == 0) ok = result > 0;
            else if (strcmp(test_mode, "deny") == 0 || strcmp(test_mode, "identity-conflict") == 0) ok = result == -1 && errno == EPERM;
            else if (strcmp(test_mode, "supervisor-death") == 0) ok = result == -1 && errno == ENOSYS;
            _exit(ok ? 0 : 125);
        }
        execvp(command[0], command);
        _exit(127);
    }
    close(sockets[1]);
    int listener = -1;
    if (profile->notify_count > 0) listener = receive_fd(sockets[0]);
    else { char ready = 0; if (read(sockets[0], &ready, 1) != 1) { close(sockets[0]); return -EIO; } }
    if (profile->notify_count > 0 && listener < 0) { close(sockets[0]); return -EIO; }
    struct process_identity expected = {0};
    int identity_result = read_process_identity(child, &expected);
    if (identity_result != 0) { if (listener >= 0) close(listener); close(sockets[0]); return identity_result; }
    if (write(sockets[0], "G", 1) != 1) { if (listener >= 0) close(listener); close(sockets[0]); return -EIO; }
    close(sockets[0]);
    if (supervisor_death && listener >= 0) {
        close(listener);
        int status = 0;
        if (waitpid(child, &status, 0) < 0) return -errno;
        if (event_count_out != NULL) *event_count_out = 0;
        return child_status_code(status);
    }
    int events = 0;
    int status = 0;
    long long deadline = monotonic_ms() + profile->deadline_ms;
    while (true) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0) { if (listener >= 0) close(listener); return -errno; }
        int remaining = (int)(deadline - monotonic_ms());
        if (remaining <= 0) { kill(child, SIGKILL); waitpid(child, &status, 0); if (listener >= 0) close(listener); return -ETIMEDOUT; }
        if (listener < 0) { usleep(1000); continue; }
        struct pollfd pollfd_value = { .fd = listener, .events = POLLIN };
        int poll_result = poll(&pollfd_value, 1, remaining > 50 ? 50 : remaining);
        if (poll_result < 0) { if (errno == EINTR) continue; close(listener); return -errno; }
        if (poll_result == 0 || !(pollfd_value.revents & POLLIN)) continue;
        struct seccomp_notif *request = NULL;
        struct seccomp_notif_resp *response = NULL;
        int allocation = seccomp_notify_alloc(&request, &response);
        if (allocation != 0) { close(listener); return allocation; }
        int receive = seccomp_notify_receive(listener, request);
        if (receive != 0) { seccomp_notify_free(request, response); if (receive == -EINTR || receive == -ENOENT) continue; close(listener); return receive; }
        bool valid = seccomp_notify_id_valid(listener, request->id) == 0;
        bool identity_ok = valid && same_identity(&expected, (pid_t)request->pid, force_identity_conflict);
        bool args_ok = identity_ok && arguments_match(profile, request);
        const struct notify_rule *rule = find_notify_rule(profile, request->data.nr);
        response->id = request->id;
        const char *decision = "deny";
        if (!valid || !identity_ok || !args_ok || rule == NULL) {
            response->error = -EPERM;
        } else if (rule->decision == DECISION_ALLOW) {
            response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            decision = "allow";
        } else if (rule->decision == DECISION_EMULATE) {
            response->val = rule->value;
            decision = "emulate";
        } else {
            response->error = -rule->error_number;
        }
        int respond = seccomp_notify_respond(listener, response);
        int stale_result = 0;
        if (respond == 0 && stale_check) stale_result = seccomp_notify_id_valid(listener, request->id);
        printf("BABYX_EVENT {\"transactionId\":\"%s\",\"pid\":%u,\"syscall\":%d,\"decision\":\"%s\",\"valid\":%s,\"identity\":%s,\"arguments\":%s,\"staleAfterResponse\":%s}\n",
            profile->transaction_id, request->pid, request->data.nr, decision, valid ? "true" : "false", identity_ok ? "true" : "false", args_ok ? "true" : "false", stale_check && stale_result != 0 ? "true" : "false");
        fflush(stdout);
        seccomp_notify_free(request, response);
        events += 1;
        if (respond != 0) { close(listener); kill(child, SIGKILL); waitpid(child, &status, 0); return respond; }
    }
    if (listener >= 0) close(listener);
    if (event_count_out != NULL) *event_count_out = events;
    return child_status_code(status);
}

static int filter_case(const char *mode, bool quiet) {
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        struct profile profile = { .default_action = SCMP_ACT_ALLOW, .deadline_ms = DEFAULT_DEADLINE_MS };
        profile.direct_count = 1;
        profile.direct_rules[0].syscall_nr = resolve_syscall("getpid");
        profile.direct_rules[0].kind = strcmp(mode, "kill") == 0 ? DIRECT_KILL : DIRECT_ERRNO;
        profile.direct_rules[0].error_number = EPERM;
        scmp_filter_ctx context = NULL;
        if (install_seccomp(&profile, &context) != 0) _exit(126);
        seccomp_release(context);
        if (strcmp(mode, "allowed") == 0) _exit(syscall(SYS_getppid) > 0 ? 0 : 127);
        errno = 0;
        long result = syscall(SYS_getpid);
        if (strcmp(mode, "errno") == 0) _exit(result == -1 && errno == EPERM ? 0 : 127);
        _exit(127);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) return -errno;
    bool ok = strcmp(mode, "kill") == 0 ? (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) : (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (!quiet) printf("{\"ok\":%s,\"case\":\"%s\",\"status\":%d}\n", ok ? "true" : "false", mode, status);
    return ok ? 0 : -EIO;
}

static int notify_case(const char *mode, bool quiet) {
    struct profile profile = { .default_action = SCMP_ACT_ALLOW, .deadline_ms = DEFAULT_DEADLINE_MS };
    strcpy(profile.transaction_id, "native-notify-test");
    profile.notify_count = 1;
    profile.notify_rules[0].syscall_nr = resolve_syscall("getpid");
    strcpy(profile.notify_rules[0].syscall_name, "getpid");
    profile.notify_rules[0].decision = strcmp(mode, "deny") == 0 || strcmp(mode, "identity-conflict") == 0 ? DECISION_DENY : DECISION_ALLOW;
    profile.notify_rules[0].error_number = EPERM;
    int events = 0;
    int status = supervise(&profile, NULL, mode, strcmp(mode, "identity-conflict") == 0, strcmp(mode, "supervisor-death") == 0, strcmp(mode, "stale") == 0, &events);
    bool ok = status == 0;
    if (!quiet) printf("BABYX_RESULT {\"ok\":%s,\"case\":\"%s\",\"events\":%d,\"status\":%d}\n", ok ? "true" : "false", mode, events, status);
    return ok ? 0 : -EIO;
}

static int landlock_case(const char *allowed_file, const char *denied_file) {
    char allowed_path[4096];
    if (strlen(allowed_file) >= sizeof(allowed_path)) return -ENAMETOOLONG;
    strcpy(allowed_path, allowed_file);
    char *slash = strrchr(allowed_path, '/');
    if (slash == NULL || slash == allowed_path) return -EINVAL;
    *slash = '\0';
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        struct profile profile = {0};
        profile.path_count = 1;
        strcpy(profile.paths[0].path, allowed_path);
        profile.paths[0].writable = false;
        int abi = 0;
        if (apply_landlock(&profile, &abi) != 0) _exit(126);
        errno = 0;
        int allowed = open(allowed_file, O_RDONLY | O_CLOEXEC);
        int allowed_error = errno;
        if (allowed >= 0) close(allowed);
        errno = 0;
        int denied = open(denied_file, O_RDONLY | O_CLOEXEC);
        int denied_error = errno;
        if (denied >= 0) close(denied);
        _exit(allowed >= 0 && allowed_error == 0 && denied < 0 && (denied_error == EACCES || denied_error == EPERM) ? 0 : 127);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) return -errno;
    bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("{\"ok\":%s,\"abi\":%d,\"allowed\":true,\"denied\":%s}\n", ok ? "true" : "false", landlock_abi(), ok ? "true" : "false");
    return ok ? 0 : -EIO;
}

static void add_direct_rule(struct profile *profile, enum direct_kind kind, const char *value) {
    if (profile->direct_count >= MAX_RULES) { errno = E2BIG; fail("too_many_rules"); }
    char name[64], parameter[64], unused[2];
    if (kind == DIRECT_ERRNO) split3(value, name, sizeof(name), parameter, sizeof(parameter), unused, sizeof(unused));
    else {
        if (strlen(value) >= sizeof(name)) { errno = EINVAL; fail("invalid_syscall_name"); }
        strcpy(name, value); parameter[0] = '\0';
    }
    struct direct_rule *rule = &profile->direct_rules[profile->direct_count++];
    rule->kind = kind;
    rule->syscall_nr = resolve_syscall(name);
    rule->error_number = kind == DIRECT_ERRNO ? parse_positive_int(parameter, "invalid_errno", 4095) : 0;
    strcpy(rule->syscall_name, name);
}

static void add_notify_rule(struct profile *profile, const char *value) {
    if (profile->notify_count >= MAX_RULES) { errno = E2BIG; fail("too_many_notify_rules"); }
    char name[64], decision[64], parameter[64];
    split3(value, name, sizeof(name), decision, sizeof(decision), parameter, sizeof(parameter));
    struct notify_rule *rule = &profile->notify_rules[profile->notify_count++];
    rule->syscall_nr = resolve_syscall(name);
    strcpy(rule->syscall_name, name);
    if (strcmp(decision, "allow") == 0) rule->decision = DECISION_ALLOW;
    else if (strcmp(decision, "deny") == 0) { rule->decision = DECISION_DENY; rule->error_number = parameter[0] == '\0' ? EPERM : parse_positive_int(parameter, "invalid_errno", 4095); }
    else if (strcmp(decision, "emulate") == 0) { rule->decision = DECISION_EMULATE; rule->value = (int64_t)parse_u64(parameter, "invalid_emulation_value"); }
    else { errno = EINVAL; fail("invalid_notify_decision"); }
}

static void add_constraint(struct profile *profile, const char *value) {
    if (profile->constraint_count >= MAX_CONSTRAINTS) { errno = E2BIG; fail("too_many_constraints"); }
    char name[64], index[32], expected[64];
    split3(value, name, sizeof(name), index, sizeof(index), expected, sizeof(expected));
    struct argument_constraint *constraint = &profile->constraints[profile->constraint_count++];
    constraint->syscall_nr = resolve_syscall(name);
    constraint->index = (unsigned int)parse_u64(index, "invalid_argument_index");
    if (constraint->index > 5) { errno = EINVAL; fail("invalid_argument_index"); }
    constraint->value = parse_u64(expected, "invalid_argument_value");
}

static void add_path(struct profile *profile, const char *path, bool writable) {
    if (profile->path_count >= MAX_PATHS || path[0] != '/' || strlen(path) >= sizeof(profile->paths[0].path)) { errno = EINVAL; fail("invalid_landlock_path"); }
    strcpy(profile->paths[profile->path_count].path, path);
    profile->paths[profile->path_count].writable = writable;
    profile->path_count += 1;
}

static void add_port(struct profile *profile, const char *value, bool bind) {
    if (profile->port_count >= MAX_PORTS) { errno = E2BIG; fail("too_many_landlock_ports"); }
    uint64_t port = parse_u64(value, "invalid_landlock_port");
    if (port > 65535) { errno = EINVAL; fail("invalid_landlock_port"); }
    profile->ports[profile->port_count].port = port;
    profile->ports[profile->port_count].bind = bind;
    profile->port_count += 1;
}

static uint32_t parse_default(const char *value) {
    if (strcmp(value, "allow") == 0) return SCMP_ACT_ALLOW;
    if (strcmp(value, "kill") == 0) return SCMP_ACT_KILL_PROCESS;
    if (strncmp(value, "errno:", 6) == 0) return SCMP_ACT_ERRNO(parse_positive_int(value + 6, "invalid_default_errno", 4095));
    errno = EINVAL;
    fail("invalid_default_action");
    return SCMP_ACT_KILL_PROCESS;
}

static int run_command(int argc, char **argv) {
    struct profile profile = { .default_action = SCMP_ACT_ALLOW, .deadline_ms = DEFAULT_DEADLINE_MS };
    strcpy(profile.transaction_id, "unbound");
    int command_index = -1;
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) { command_index = i + 1; break; }
        if (i + 1 >= argc) { errno = EINVAL; fail("missing_option_value"); }
        const char *option = argv[i];
        const char *value = argv[++i];
        if (strcmp(option, "--transaction") == 0) {
            if (!safe_identifier(value)) { errno = EINVAL; fail("invalid_transaction_id"); }
            strcpy(profile.transaction_id, value);
        } else if (strcmp(option, "--deadline-ms") == 0) profile.deadline_ms = parse_positive_int(value, "invalid_deadline", 60000);
        else if (strcmp(option, "--default") == 0) profile.default_action = parse_default(value);
        else if (strcmp(option, "--allow") == 0) add_direct_rule(&profile, DIRECT_ALLOW, value);
        else if (strcmp(option, "--errno") == 0) add_direct_rule(&profile, DIRECT_ERRNO, value);
        else if (strcmp(option, "--kill") == 0) add_direct_rule(&profile, DIRECT_KILL, value);
        else if (strcmp(option, "--notify") == 0) add_notify_rule(&profile, value);
        else if (strcmp(option, "--arg-eq") == 0) add_constraint(&profile, value);
        else if (strcmp(option, "--landlock-read") == 0) add_path(&profile, value, false);
        else if (strcmp(option, "--landlock-write") == 0) add_path(&profile, value, true);
        else if (strcmp(option, "--landlock-bind-port") == 0) add_port(&profile, value, true);
        else if (strcmp(option, "--landlock-connect-port") == 0) add_port(&profile, value, false);
        else { errno = EINVAL; fail("unknown_option"); }
    }
    if (command_index < 0 || command_index >= argc) { errno = EINVAL; fail("missing_command"); }
    int events = 0;
    int status = supervise(&profile, &argv[command_index], NULL, false, false, false, &events);
    printf("BABYX_RESULT {\"ok\":%s,\"transactionId\":\"%s\",\"status\":%d,\"events\":%d,\"droppedEvents\":0}\n", status == 0 ? "true" : "false", profile.transaction_id, status, events);
    return status;
}

static int raw_syscall_case(const char *name) {
    long result = -1;
    if (strcmp(name, "getpid") == 0) result = syscall(SYS_getpid);
    else if (strcmp(name, "getppid") == 0) result = syscall(SYS_getppid);
    else { errno = EINVAL; fail("unsupported_raw_syscall"); }
    int saved_errno = errno;
    printf("{\"ok\":%s,\"syscall\":\"%s\",\"result\":%ld,\"errno\":%d}\n", result >= 0 ? "true" : "false", name, result, saved_errno);
    return result >= 0 ? 0 : 1;
}

static int probe_component(const char *component) {
    const struct scmp_version *version = seccomp_version();
    if (strcmp(component, "filter") == 0) {
        int result = filter_case("errno", true);
        printf("{\"ok\":%s,\"component\":\"filter\",\"libseccomp\":\"%u.%u.%u\",\"api\":%u}\n", result == 0 ? "true" : "false", version->major, version->minor, version->micro, seccomp_api_get());
        return result == 0 ? 0 : 1;
    }
    if (strcmp(component, "notify") == 0) {
        int result = notify_case("allow", true);
        printf("{\"ok\":%s,\"component\":\"notify\",\"libseccomp\":\"%u.%u.%u\",\"api\":%u}\n", result == 0 ? "true" : "false", version->major, version->minor, version->micro, seccomp_api_get());
        return result == 0 ? 0 : 1;
    }
    if (strcmp(component, "landlock") == 0) {
        int abi = landlock_abi();
        printf("{\"ok\":%s,\"component\":\"landlock\",\"abi\":%d,\"networkRestrictions\":%s}\n", abi > 0 ? "true" : "false", abi, abi >= 4 ? "true" : "false");
        return abi > 0 ? 0 : 1;
    }
    errno = EINVAL;
    fail("unknown_probe_component");
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "describe") == 0) {
        const struct scmp_version *version = seccomp_version();
        printf("{\"product\":\"baby-x-mediation-supervisor\",\"version\":\"1.0.0\",\"libseccomp\":\"%u.%u.%u\",\"architecture\":%u,\"actions\":[\"describe\",\"probe\",\"filter-test\",\"notify-test\",\"landlock-test\",\"raw-syscall\",\"run\"]}\n", version->major, version->minor, version->micro, seccomp_arch_native());
        return 0;
    }
    if (strcmp(argv[1], "probe") == 0) {
        if (argc != 3) { errno = EINVAL; fail("probe_requires_component"); }
        return probe_component(argv[2]);
    }
    if (strcmp(argv[1], "filter-test") == 0) {
        if (argc != 3 || (strcmp(argv[2], "allowed") != 0 && strcmp(argv[2], "errno") != 0 && strcmp(argv[2], "kill") != 0)) { errno = EINVAL; fail("invalid_filter_test"); }
        return filter_case(argv[2], false) == 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "notify-test") == 0) {
        if (argc != 3 || (strcmp(argv[2], "allow") != 0 && strcmp(argv[2], "deny") != 0 && strcmp(argv[2], "stale") != 0 && strcmp(argv[2], "identity-conflict") != 0 && strcmp(argv[2], "supervisor-death") != 0)) { errno = EINVAL; fail("invalid_notify_test"); }
        return notify_case(argv[2], false) == 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "landlock-test") == 0) {
        if (argc != 4) { errno = EINVAL; fail("landlock_test_requires_files"); }
        return landlock_case(argv[2], argv[3]) == 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "raw-syscall") == 0) {
        if (argc != 3) { errno = EINVAL; fail("raw_syscall_requires_name"); }
        return raw_syscall_case(argv[2]);
    }
    if (strcmp(argv[1], "run") == 0) return run_command(argc, argv);
    errno = EINVAL;
    fail("unknown_action");
    return 1;
}

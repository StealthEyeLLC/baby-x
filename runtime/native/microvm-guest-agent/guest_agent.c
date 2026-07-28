#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <linux/vm_sockets.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PORT 5000
#define MAX_REQUEST 8192
#define MAX_TASKS 32
#define TOKEN_HEX 64
#define IDENTITY_HEX 64

typedef enum { TASK_EMPTY, TASK_RUNNING, TASK_COMPLETED, TASK_CANCELLED, TASK_FAILED } task_state;
typedef struct { char id[65]; task_state state; unsigned sleep_ms; bool cancel; } task;
typedef struct { int fd; unsigned peer_cid; } client_args;

static task tasks[MAX_TASKS];
static pthread_mutex_t tasks_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t auth_mu = PTHREAD_MUTEX_INITIALIZER;
static char auth_token[TOKEN_HEX + 1];
static char workload_identity[IDENTITY_HEX + 1];
static char random_epoch[IDENTITY_HEX + 1];
static bool auth_ready = false;

static void logline(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  fflush(stderr);
  va_end(ap);
}

static bool write_all(int fd, const char *data, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t written = write(fd, data + offset, length - offset);
    if (written < 0) { if (errno == EINTR) continue; return false; }
    if (written == 0) return false;
    offset += (size_t)written;
  }
  return true;
}

static void respond(int fd, const char *fmt, ...) {
  char out[4096];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(out, sizeof(out), fmt, ap);
  va_end(ap);
  if (n < 0) return;
  size_t len = (size_t)n;
  if (len >= sizeof(out)) len = sizeof(out) - 1;
  if (!write_all(fd, out, len)) return;
  (void)write_all(fd, "\n", 1);
}

static void secure_clear(void *value, size_t length) {
  volatile unsigned char *cursor = (volatile unsigned char *)value;
  while (length-- > 0) *cursor++ = 0;
}

static int from_hex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool valid_fixed_hex(const char *value, size_t length) {
  if (strlen(value) != length) return false;
  for (size_t i = 0; i < length; i++) if (from_hex(value[i]) < 0) return false;
  return true;
}

static bool random_hex(char out[IDENTITY_HEX + 1]) {
  unsigned char bytes[IDENTITY_HEX / 2];
  size_t offset = 0;
  while (offset < sizeof(bytes)) {
    ssize_t count = getrandom(bytes + offset, sizeof(bytes) - offset, 0);
    if (count < 0) { if (errno == EINTR) continue; secure_clear(bytes, sizeof(bytes)); return false; }
    offset += (size_t)count;
  }
  static const char alphabet[] = "0123456789abcdef";
  for (size_t i = 0; i < sizeof(bytes); i++) {
    out[i * 2] = alphabet[bytes[i] >> 4];
    out[i * 2 + 1] = alphabet[bytes[i] & 0x0f];
  }
  out[IDENTITY_HEX] = '\0';
  secure_clear(bytes, sizeof(bytes));
  return true;
}

static bool load_token_file(char out[TOKEN_HEX + 1]) {
  int fd = open("/etc/babyx-auth-token", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  ssize_t count = read(fd, out, TOKEN_HEX + 1);
  close(fd);
  if (count != TOKEN_HEX) { secure_clear(out, TOKEN_HEX + 1); return false; }
  out[TOKEN_HEX] = '\0';
  if (!valid_fixed_hex(out, TOKEN_HEX)) { secure_clear(out, TOKEN_HEX + 1); return false; }
  if (unlink("/etc/babyx-auth-token") != 0 && errno != ENOENT) { secure_clear(out, TOKEN_HEX + 1); return false; }
  sync();
  return true;
}

static bool install_auth_state(const char *token) {
  if (!valid_fixed_hex(token, TOKEN_HEX)) return false;
  char identity[IDENTITY_HEX + 1];
  char epoch[IDENTITY_HEX + 1];
  if (!random_hex(identity) || !random_hex(epoch)) {
    secure_clear(identity, sizeof(identity));
    secure_clear(epoch, sizeof(epoch));
    return false;
  }
  pthread_mutex_lock(&auth_mu);
  memcpy(auth_token, token, TOKEN_HEX + 1);
  memcpy(workload_identity, identity, IDENTITY_HEX + 1);
  memcpy(random_epoch, epoch, IDENTITY_HEX + 1);
  auth_ready = true;
  pthread_mutex_unlock(&auth_mu);
  secure_clear(identity, sizeof(identity));
  secure_clear(epoch, sizeof(epoch));
  return true;
}

static bool ensure_auth_state(void) {
  pthread_mutex_lock(&auth_mu);
  bool ready = auth_ready;
  pthread_mutex_unlock(&auth_mu);
  if (ready) return true;
  char token[TOKEN_HEX + 1] = {0};
  if (!load_token_file(token)) return false;
  bool installed = install_auth_state(token);
  secure_clear(token, sizeof(token));
  return installed;
}

static void clear_auth_state(void) {
  pthread_mutex_lock(&auth_mu);
  secure_clear(auth_token, sizeof(auth_token));
  secure_clear(workload_identity, sizeof(workload_identity));
  secure_clear(random_epoch, sizeof(random_epoch));
  auth_ready = false;
  pthread_mutex_unlock(&auth_mu);
}

static bool authenticate(const char *token) {
  if (!ensure_auth_state()) return false;
  unsigned difference = 0;
  pthread_mutex_lock(&auth_mu);
  if (!auth_ready || strlen(token) != TOKEN_HEX) difference = 1;
  else for (size_t i = 0; i < TOKEN_HEX; i++) difference |= (unsigned)(auth_token[i] ^ token[i]);
  pthread_mutex_unlock(&auth_mu);
  return difference == 0;
}

static bool bootstrap_auth(const char *line, unsigned peer_cid) {
  static const char prefix[] = "BOOTSTRAP ";
  if (peer_cid != VMADDR_CID_HOST || strncmp(line, prefix, sizeof(prefix) - 1) != 0) return false;
  pthread_mutex_lock(&auth_mu);
  bool ready = auth_ready;
  pthread_mutex_unlock(&auth_mu);
  if (ready) return false;
  return install_auth_state(line + sizeof(prefix) - 1);
}

static bool safe_id(const char *value) {
  size_t length = strlen(value);
  if (length < 8 || length > 64) return false;
  for (size_t i = 0; i < length; i++) {
    char c = value[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
  }
  return true;
}

static const char *state_name(task_state state) {
  switch (state) {
    case TASK_RUNNING: return "RUNNING";
    case TASK_COMPLETED: return "COMPLETED";
    case TASK_CANCELLED: return "CANCELLED";
    case TASK_FAILED: return "FAILED";
    default: return "UNKNOWN";
  }
}

static task *find_task(const char *id) {
  for (int i = 0; i < MAX_TASKS; i++) if (tasks[i].state != TASK_EMPTY && strcmp(tasks[i].id, id) == 0) return &tasks[i];
  return NULL;
}

static task *allocate_task(const char *id) {
  if (find_task(id) != NULL) return NULL;
  for (int i = 0; i < MAX_TASKS; i++) {
    if (tasks[i].state == TASK_EMPTY) {
      memset(&tasks[i], 0, sizeof(tasks[i]));
      snprintf(tasks[i].id, sizeof(tasks[i].id), "%s", id);
      tasks[i].state = TASK_RUNNING;
      return &tasks[i];
    }
  }
  return NULL;
}

static bool task_table_empty(void) {
  bool empty = true;
  pthread_mutex_lock(&tasks_mu);
  for (int i = 0; i < MAX_TASKS; i++) if (tasks[i].state != TASK_EMPTY) { empty = false; break; }
  pthread_mutex_unlock(&tasks_mu);
  return empty;
}

static void *sleep_worker(void *argument) {
  task *current = (task *)argument;
  unsigned elapsed = 0;
  while (elapsed < current->sleep_ms) {
    usleep(10000);
    elapsed += 10;
    pthread_mutex_lock(&tasks_mu);
    bool cancelled = current->cancel;
    pthread_mutex_unlock(&tasks_mu);
    if (cancelled) {
      pthread_mutex_lock(&tasks_mu);
      current->state = TASK_CANCELLED;
      pthread_mutex_unlock(&tasks_mu);
      return NULL;
    }
  }
  pthread_mutex_lock(&tasks_mu);
  current->state = TASK_COMPLETED;
  pthread_mutex_unlock(&tasks_mu);
  return NULL;
}

static bool valid_variable_hex(const char *value) {
  size_t length = strlen(value);
  if (length > 2048 || length % 2 != 0) return false;
  for (size_t i = 0; i < length; i++) if (from_hex(value[i]) < 0) return false;
  return true;
}

static void health_response(int fd) {
  char boot_id[64] = "unknown";
  int boot_fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (boot_fd >= 0) {
    ssize_t count = read(boot_fd, boot_id, sizeof(boot_id) - 1);
    close(boot_fd);
    if (count > 0) {
      boot_id[count] = '\0';
      char *newline = strchr(boot_id, '\n');
      if (newline != NULL) *newline = '\0';
    }
  }
  char identity[IDENTITY_HEX + 1];
  char epoch[IDENTITY_HEX + 1];
  pthread_mutex_lock(&auth_mu);
  snprintf(identity, sizeof(identity), "%s", workload_identity);
  snprintf(epoch, sizeof(epoch), "%s", random_epoch);
  pthread_mutex_unlock(&auth_mu);
  respond(fd, "{\"ok\":true,\"agent\":\"baby-x-guest-agent\",\"version\":\"1.1.0\",\"network\":\"NONE\",\"bootId\":\"%s\",\"workloadIdentity\":\"%s\",\"randomEpoch\":\"%s\"}", boot_id, identity, epoch);
  secure_clear(identity, sizeof(identity));
  secure_clear(epoch, sizeof(epoch));
}

static void handle_command(int fd, char *command) {
  char *save = NULL;
  char *verb = strtok_r(command, " \t\r\n", &save);
  if (verb == NULL) { respond(fd, "{\"ok\":false,\"error\":\"EMPTY\"}"); return; }
  if (strcmp(verb, "HEALTH") == 0) { health_response(fd); return; }
  if (strcmp(verb, "ROTATE_IDENTITY") == 0) {
    if (!task_table_empty()) { respond(fd, "{\"ok\":false,\"error\":\"CONTAMINATED_TASK_STATE\"}"); return; }
    char identity[IDENTITY_HEX + 1];
    char epoch[IDENTITY_HEX + 1];
    if (!random_hex(identity) || !random_hex(epoch)) { respond(fd, "{\"ok\":false,\"error\":\"RANDOMNESS_FAILED\"}"); return; }
    pthread_mutex_lock(&auth_mu);
    memcpy(workload_identity, identity, sizeof(identity));
    memcpy(random_epoch, epoch, sizeof(epoch));
    pthread_mutex_unlock(&auth_mu);
    respond(fd, "{\"ok\":true,\"workloadIdentity\":\"%s\",\"randomEpoch\":\"%s\"}", identity, epoch);
    secure_clear(identity, sizeof(identity));
    secure_clear(epoch, sizeof(epoch));
    return;
  }
  if (strcmp(verb, "PREPARE_SNAPSHOT") == 0) {
    if (!task_table_empty()) { respond(fd, "{\"ok\":false,\"error\":\"CONTAMINATED_TASK_STATE\"}"); return; }
    sync();
    respond(fd, "{\"ok\":true,\"taskStateEmpty\":true,\"credentialCleared\":true,\"identityCleared\":true}");
    clear_auth_state();
    return;
  }
  if (strcmp(verb, "EXEC") == 0) {
    char *kind = strtok_r(NULL, " \t\r\n", &save);
    char *id = strtok_r(NULL, " \t\r\n", &save);
    char *argument = strtok_r(NULL, " \t\r\n", &save);
    if (kind == NULL || id == NULL || !safe_id(id)) { respond(fd, "{\"ok\":false,\"error\":\"INVALID_TASK\"}"); return; }
    if (strcmp(kind, "ECHO_HEX") == 0) {
      if (argument == NULL || !valid_variable_hex(argument)) { respond(fd, "{\"ok\":false,\"error\":\"INVALID_HEX\"}"); return; }
      respond(fd, "{\"ok\":true,\"taskId\":\"%s\",\"state\":\"COMPLETED\",\"resultHex\":\"%s\"}", id, argument);
      return;
    }
    if (strcmp(kind, "SLEEP_MS") == 0) {
      if (argument == NULL) { respond(fd, "{\"ok\":false,\"error\":\"INVALID_DURATION\"}"); return; }
      char *end = NULL;
      unsigned long milliseconds = strtoul(argument, &end, 10);
      if (*argument == '\0' || *end != '\0' || milliseconds > 60000) { respond(fd, "{\"ok\":false,\"error\":\"INVALID_DURATION\"}"); return; }
      pthread_mutex_lock(&tasks_mu);
      task *current = allocate_task(id);
      if (current != NULL) current->sleep_ms = (unsigned)milliseconds;
      pthread_mutex_unlock(&tasks_mu);
      if (current == NULL) { respond(fd, "{\"ok\":false,\"error\":\"TASK_CONFLICT_OR_CAPACITY\"}"); return; }
      pthread_t thread;
      if (pthread_create(&thread, NULL, sleep_worker, current) != 0) {
        pthread_mutex_lock(&tasks_mu);
        current->state = TASK_FAILED;
        pthread_mutex_unlock(&tasks_mu);
        respond(fd, "{\"ok\":false,\"error\":\"TASK_START_FAILED\"}");
        return;
      }
      pthread_detach(thread);
      respond(fd, "{\"ok\":true,\"taskId\":\"%s\",\"state\":\"RUNNING\"}", id);
      return;
    }
    respond(fd, "{\"ok\":false,\"error\":\"UNKNOWN_TASK_KIND\"}");
    return;
  }
  if (strcmp(verb, "STATUS") == 0 || strcmp(verb, "CANCEL") == 0) {
    char *id = strtok_r(NULL, " \t\r\n", &save);
    if (id == NULL || !safe_id(id)) { respond(fd, "{\"ok\":false,\"error\":\"INVALID_TASK\"}"); return; }
    pthread_mutex_lock(&tasks_mu);
    task *current = find_task(id);
    if (current != NULL && strcmp(verb, "CANCEL") == 0 && current->state == TASK_RUNNING) current->cancel = true;
    task_state state = current != NULL ? current->state : TASK_EMPTY;
    pthread_mutex_unlock(&tasks_mu);
    if (current == NULL) { respond(fd, "{\"ok\":false,\"error\":\"TASK_NOT_FOUND\"}"); return; }
    respond(fd, "{\"ok\":true,\"taskId\":\"%s\",\"state\":\"%s\"}", id, state_name(state));
    return;
  }
  if (strcmp(verb, "SHUTDOWN") == 0) {
    respond(fd, "{\"ok\":true,\"state\":\"SHUTTING_DOWN\"}");
    sync();
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    return;
  }
  respond(fd, "{\"ok\":false,\"error\":\"UNKNOWN_COMMAND\"}");
}

static void *client_thread(void *argument) {
  client_args *args = (client_args *)argument;
  int fd = args->fd;
  unsigned peer_cid = args->peer_cid;
  free(args);
  char buffer[MAX_REQUEST + 1];
  size_t used = 0;
  while (used < MAX_REQUEST) {
    ssize_t count = read(fd, buffer + used, MAX_REQUEST - used);
    if (count <= 0) break;
    used += (size_t)count;
    char *first = memchr(buffer, '\n', used);
    if (first != NULL && memchr(first + 1, '\n', used - (size_t)(first + 1 - buffer)) != NULL) break;
  }
  buffer[used] = '\0';
  char *first = strchr(buffer, '\n');
  if (first == NULL) { respond(fd, "{\"ok\":false,\"error\":\"MALFORMED\"}"); close(fd); return NULL; }
  *first = '\0';
  char *command = first + 1;
  char *end = strchr(command, '\n');
  if (end != NULL) *end = '\0';
  if (bootstrap_auth(buffer, peer_cid)) {
    health_response(fd);
    close(fd);
    return NULL;
  }
  if (!authenticate(buffer)) {
    respond(fd, "{\"ok\":false,\"error\":\"AUTHENTICATION_FAILED\"}");
    close(fd);
    return NULL;
  }
  handle_command(fd, command);
  close(fd);
  return NULL;
}

static void mount_if(const char *source, const char *target, const char *type, unsigned long flags, const char *data) {
  mkdir(target, 0755);
  if (mount(source, target, type, flags, data) != 0 && errno != EBUSY) logline("mount %s failed: %s", target, strerror(errno));
}

int main(void) {
  if (getpid() != 1) { fprintf(stderr, "guest agent must be pid 1\n"); return 2; }
  umask(077);
  mount_if("proc", "/proc", "proc", 0, NULL);
  mount_if("sysfs", "/sys", "sysfs", 0, NULL);
  mount_if("devtmpfs", "/dev", "devtmpfs", 0, "mode=0755");
  mount_if("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=16m");
  if (!ensure_auth_state()) { logline("initial authentication token missing or invalid"); return 111; }
  signal(SIGPIPE, SIG_IGN);
  int server = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (server < 0) { logline("vsock socket failed: %s", strerror(errno)); return 120; }
  struct sockaddr_vm address = { .svm_family = AF_VSOCK, .svm_port = PORT, .svm_cid = VMADDR_CID_ANY };
  if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) { logline("vsock bind failed: %s", strerror(errno)); return 121; }
  if (listen(server, 32) != 0) return 122;
  logline("BABYX_GUEST_READY port=%d", PORT);
  for (;;) {
    struct sockaddr_vm peer = {0};
    socklen_t peer_length = sizeof(peer);
    int client = accept4(server, (struct sockaddr *)&peer, &peer_length, SOCK_CLOEXEC);
    if (client < 0) { if (errno == EINTR) continue; return 123; }
    client_args *args = calloc(1, sizeof(*args));
    if (args == NULL) { close(client); continue; }
    args->fd = client;
    args->peer_cid = peer.svm_cid;
    pthread_t thread;
    if (pthread_create(&thread, NULL, client_thread, args) != 0) { free(args); close(client); continue; }
    pthread_detach(thread);
  }
}

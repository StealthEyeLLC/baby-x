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
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PORT 5000
#define MAX_REQUEST 8192
#define MAX_TASKS 32
#define TOKEN_HEX 64

typedef enum { TASK_EMPTY, TASK_RUNNING, TASK_COMPLETED, TASK_CANCELLED, TASK_FAILED } task_state;
typedef struct { char id[65]; task_state state; unsigned sleep_ms; bool cancel; } task;
static task tasks[MAX_TASKS];
static pthread_mutex_t tasks_mu = PTHREAD_MUTEX_INITIALIZER;
static char auth_token[TOKEN_HEX + 1];

static void logline(const char *fmt, ...) {
  va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); fputc('\n', stderr); fflush(stderr); va_end(ap);
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
static bool safe_id(const char *s) {
  size_t n=strlen(s); if(n<8||n>64) return false;
  for(size_t i=0;i<n;i++) if(!((s[i]>='a'&&s[i]<='z')||(s[i]>='A'&&s[i]<='Z')||(s[i]>='0'&&s[i]<='9')||s[i]=='_'||s[i]=='-')) return false;
  return true;
}
static const char *state_name(task_state s) {
  switch(s){case TASK_RUNNING:return "RUNNING";case TASK_COMPLETED:return "COMPLETED";case TASK_CANCELLED:return "CANCELLED";case TASK_FAILED:return "FAILED";default:return "UNKNOWN";}
}
static task *find_task(const char *id) { for(int i=0;i<MAX_TASKS;i++) if(tasks[i].state!=TASK_EMPTY&&strcmp(tasks[i].id,id)==0) return &tasks[i]; return NULL; }
static task *allocate_task(const char *id) {
  if(find_task(id)) return NULL;
  for(int i=0;i<MAX_TASKS;i++) if(tasks[i].state==TASK_EMPTY){ memset(&tasks[i],0,sizeof(tasks[i])); snprintf(tasks[i].id,sizeof(tasks[i].id),"%s",id); tasks[i].state=TASK_RUNNING; return &tasks[i]; }
  return NULL;
}
static void *sleep_worker(void *arg) {
  task *t=(task*)arg; unsigned elapsed=0;
  while(elapsed<t->sleep_ms){ usleep(10000); elapsed+=10; pthread_mutex_lock(&tasks_mu); bool cancelled=t->cancel; pthread_mutex_unlock(&tasks_mu); if(cancelled){ pthread_mutex_lock(&tasks_mu); t->state=TASK_CANCELLED; pthread_mutex_unlock(&tasks_mu); return NULL; } }
  pthread_mutex_lock(&tasks_mu); t->state=TASK_COMPLETED; pthread_mutex_unlock(&tasks_mu); return NULL;
}
static int from_hex(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static bool valid_hex(const char *s){ size_t n=strlen(s); if(n>2048||n%2) return false; for(size_t i=0;i<n;i++) if(from_hex(s[i])<0)return false; return true; }
static void handle_command(int fd, char *cmd) {
  char *save=NULL; char *verb=strtok_r(cmd," \t\r\n",&save); if(!verb){respond(fd,"{\"ok\":false,\"error\":\"EMPTY\"}");return;}
  if(strcmp(verb,"HEALTH")==0){
    char boot_id[64] = "unknown";
    int boot_fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (boot_fd >= 0) {
      ssize_t boot_n = read(boot_fd, boot_id, sizeof(boot_id) - 1);
      close(boot_fd);
      if (boot_n > 0) {
        boot_id[boot_n] = '\0';
        char *newline = strchr(boot_id, '\n');
        if (newline != NULL) *newline = '\0';
      }
    }
    respond(fd,"{\"ok\":true,\"agent\":\"baby-x-guest-agent\",\"version\":\"1.0.0\",\"network\":\"NONE\",\"bootId\":\"%s\"}", boot_id);
    return;
  }
  if(strcmp(verb,"EXEC")==0){
    char *kind=strtok_r(NULL," \t\r\n",&save); char *id=strtok_r(NULL," \t\r\n",&save); char *arg=strtok_r(NULL," \t\r\n",&save);
    if(!kind||!id||!safe_id(id)){respond(fd,"{\"ok\":false,\"error\":\"INVALID_TASK\"}");return;}
    if(strcmp(kind,"ECHO_HEX")==0){ if(!arg||!valid_hex(arg)){respond(fd,"{\"ok\":false,\"error\":\"INVALID_HEX\"}");return;} respond(fd,"{\"ok\":true,\"taskId\":\"%s\",\"state\":\"COMPLETED\",\"resultHex\":\"%s\"}",id,arg); return; }
    if(strcmp(kind,"SLEEP_MS")==0){
      if(!arg){respond(fd,"{\"ok\":false,\"error\":\"INVALID_DURATION\"}");return;} char *end=NULL; unsigned long ms=strtoul(arg,&end,10); if(*arg=='\0'||*end!='\0'||ms>60000){respond(fd,"{\"ok\":false,\"error\":\"INVALID_DURATION\"}");return;}
      pthread_mutex_lock(&tasks_mu); task *t=allocate_task(id); if(t)t->sleep_ms=(unsigned)ms; pthread_mutex_unlock(&tasks_mu); if(!t){respond(fd,"{\"ok\":false,\"error\":\"TASK_CONFLICT_OR_CAPACITY\"}");return;}
      pthread_t th; if(pthread_create(&th,NULL,sleep_worker,t)!=0){pthread_mutex_lock(&tasks_mu);t->state=TASK_FAILED;pthread_mutex_unlock(&tasks_mu);respond(fd,"{\"ok\":false,\"error\":\"TASK_START_FAILED\"}");return;} pthread_detach(th);
      respond(fd,"{\"ok\":true,\"taskId\":\"%s\",\"state\":\"RUNNING\"}",id); return;
    }
    respond(fd,"{\"ok\":false,\"error\":\"UNKNOWN_TASK_KIND\"}"); return;
  }
  if(strcmp(verb,"STATUS")==0||strcmp(verb,"CANCEL")==0){
    char *id=strtok_r(NULL," \t\r\n",&save); if(!id||!safe_id(id)){respond(fd,"{\"ok\":false,\"error\":\"INVALID_TASK\"}");return;}
    pthread_mutex_lock(&tasks_mu); task *t=find_task(id); if(t&&strcmp(verb,"CANCEL")==0&&t->state==TASK_RUNNING)t->cancel=true; task_state state=t?t->state:TASK_EMPTY; pthread_mutex_unlock(&tasks_mu);
    if(!t){respond(fd,"{\"ok\":false,\"error\":\"TASK_NOT_FOUND\"}");return;} respond(fd,"{\"ok\":true,\"taskId\":\"%s\",\"state\":\"%s\"}",id,state_name(state)); return;
  }
  if(strcmp(verb,"SHUTDOWN")==0){ respond(fd,"{\"ok\":true,\"state\":\"SHUTTING_DOWN\"}"); sync(); reboot(LINUX_REBOOT_CMD_POWER_OFF); return; }
  respond(fd,"{\"ok\":false,\"error\":\"UNKNOWN_COMMAND\"}");
}
static void *client_thread(void *arg) {
  int fd=(int)(intptr_t)arg; char buf[MAX_REQUEST+1]; size_t used=0;
  while(used<MAX_REQUEST){ ssize_t n=read(fd,buf+used,MAX_REQUEST-used); if(n<=0)break; used+=(size_t)n; if(memchr(buf,'\n',used)&&memchr((char*)memchr(buf,'\n',used)+1,'\n',used-((char*)memchr(buf,'\n',used)-buf)-1))break; }
  buf[used]='\0'; char *first=strchr(buf,'\n'); if(!first){respond(fd,"{\"ok\":false,\"error\":\"MALFORMED\"}");close(fd);return NULL;} *first='\0'; char *cmd=first+1; char *end=strchr(cmd,'\n'); if(end)*end='\0';
  if(strlen(buf)!=TOKEN_HEX||memcmp(buf,auth_token,TOKEN_HEX)!=0){respond(fd,"{\"ok\":false,\"error\":\"AUTHENTICATION_FAILED\"}");close(fd);return NULL;}
  handle_command(fd,cmd); close(fd); return NULL;
}
static void mount_if(const char *src,const char *target,const char *type,unsigned long flags,const char *data){ mkdir(target,0755); if(mount(src,target,type,flags,data)!=0&&errno!=EBUSY)logline("mount %s failed: %s",target,strerror(errno)); }
static void read_token(void){ int fd=open("/etc/babyx-auth-token",O_RDONLY|O_CLOEXEC); if(fd<0){logline("auth token missing");_exit(111);} ssize_t n=read(fd,auth_token,TOKEN_HEX);close(fd);unlink("/etc/babyx-auth-token");if(n!=TOKEN_HEX){logline("auth token invalid");_exit(112);}auth_token[TOKEN_HEX]='\0'; for(int i=0;i<TOKEN_HEX;i++) if(from_hex(auth_token[i])<0){logline("auth token malformed");_exit(113);} }
int main(void){
  if(getpid()!=1){fprintf(stderr,"guest agent must be pid 1\n");return 2;} umask(077); mount_if("proc","/proc","proc",0,NULL);mount_if("sysfs","/sys","sysfs",0,NULL);mount_if("devtmpfs","/dev","devtmpfs",0,"mode=0755");mount_if("tmpfs","/run","tmpfs",MS_NOSUID|MS_NODEV,"mode=0755,size=16m"); read_token();
  signal(SIGPIPE,SIG_IGN); int s=socket(AF_VSOCK,SOCK_STREAM|SOCK_CLOEXEC,0); if(s<0){logline("vsock socket failed: %s",strerror(errno));return 120;} struct sockaddr_vm addr={.svm_family=AF_VSOCK,.svm_port=PORT,.svm_cid=VMADDR_CID_ANY}; if(bind(s,(struct sockaddr*)&addr,sizeof(addr))!=0){logline("vsock bind failed: %s",strerror(errno));return 121;} if(listen(s,32)!=0)return 122; logline("BABYX_GUEST_READY port=%d",PORT);
  for(;;){int c=accept4(s,NULL,NULL,SOCK_CLOEXEC);if(c<0){if(errno==EINTR)continue;return 123;}pthread_t th;if(pthread_create(&th,NULL,client_thread,(void*)(intptr_t)c)!=0){close(c);continue;}pthread_detach(th);} }

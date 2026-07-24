#include <node_api.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

static napi_value fail(napi_env env, const char* message) {
  napi_throw_error(env, nullptr, message);
  return nullptr;
}

static napi_value get_peer_credentials(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 1) {
    return fail(env, "getPeerCredentials requires one file descriptor");
  }
  int32_t fd = -1;
  if (napi_get_value_int32(env, argv[0], &fd) != napi_ok || fd < 0) {
    return fail(env, "file descriptor must be a non-negative integer");
  }
  struct ucred credential {};
  socklen_t length = sizeof(credential);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credential, &length) != 0 || length != sizeof(credential)) {
    return fail(env, std::strerror(errno));
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_value pid;
  napi_value uid;
  napi_value gid;
  napi_create_int32(env, credential.pid, &pid);
  napi_create_uint32(env, credential.uid, &uid);
  napi_create_uint32(env, credential.gid, &gid);
  napi_set_named_property(env, result, "pid", pid);
  napi_set_named_property(env, result, "uid", uid);
  napi_set_named_property(env, result, "gid", gid);
  return result;
}

static napi_value initialize(napi_env env, napi_value exports) {
  napi_value function;
  napi_create_function(env, "getPeerCredentials", NAPI_AUTO_LENGTH, get_peer_credentials, nullptr, &function);
  napi_set_named_property(env, exports, "getPeerCredentials", function);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, initialize)

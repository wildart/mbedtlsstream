#include "git2/common.h"
#include "git2/sys/stream.h"

GIT_EXTERN(int) mbedtls_stream_init(const char *file, const char *path);

GIT_EXTERN(int) mbedtls_stream_new(git_stream **out, const char *host, const char *port);

GIT_EXTERN(int) mbedtls_stream_shutdown(void);
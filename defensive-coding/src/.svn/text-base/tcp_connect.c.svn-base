#include "tcp_connect.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


int
tcp_connect(const char *host, const char *service)
{
  // A real-world implementation should connect to one IPv4 and one
  // IPv address in parallel, until a responsive server is found.
  const struct addrinfo hints = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM,
  };
  struct addrinfo *result;
  int ret = getaddrinfo(host, service, &hints, &result);
  if (ret != 0) {
    fprintf(stderr, "error: name lookup failure for %s/%s: %s\n",
	    host, service, gai_strerror(ret));
    exit(1);
  }
  if (result == NULL) {
    fprintf(stderr, "error: no addresses found for %s/%s\n", host, service);
    freeaddrinfo(result);
    return -1;
  }
  for (const struct addrinfo *ai = result; ai; ai = ai->ai_next) {
    ret = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (ret < 0) {
      continue;
    }
    if (connect(ret, ai->ai_addr, ai->ai_addrlen) == 0) {
      break;
    }
    int save = errno;
    close(ret);
    errno = save;
    ret = -1;
  }
  if (ret < 0) {
    return -1;
  }
  freeaddrinfo(result);
  return ret;
}

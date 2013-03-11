#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

//+ C Pointers-remaining
ssize_t
extract_strings(const char *in, size_t inlen, char **out, size_t outlen)
{
  const char *inp = in;
  const char *inend = in + inlen;
  char **outp = out;
  char **outend = out + outlen;

  while (inp != inend) {
    size_t len;
    char *s;
    if (outp == outend) {
      errno = ENOSPC;
      goto err;
    }
    len = (unsigned char)*inp;
    ++inp;
    if (len > (size_t)(inend - inp)) {
      errno = EINVAL;
      goto err;
    }
    s = malloc(len + 1);
    if (s == NULL) {
      goto err;
    }
    memcpy(s, inp, len);
    inp += len;
    s[len] = '\0';
    *outp = s;
    ++outp;
  }
  return outp - out;
err:
  {
    int errno_old = errno;
    while (out != outp) {
      free(*out);
      ++out;
    }
    errno = errno_old;
  }
  return -1;
}
//-

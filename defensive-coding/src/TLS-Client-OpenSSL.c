#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "tcp_connect.h"

int X509_check_host(X509 *, const unsigned char *chk, size_t chklen,
		    unsigned int flags);

static void __attribute__((noreturn))
usage(const char *progname)
{
  fprintf(stderr, "usage: %s HOST PORT\n", progname);
  exit(2);
}

static void
info_certificate_override(const char *reason, X509 *crt, const char *host)
{
  int derlen = i2d_X509(crt, NULL);
  if (derlen < 0) {
    fprintf(stderr, "error: could not DER-encode certificate\n");
    exit(1);
  }
  unsigned char *der = malloc(derlen);
  if (der == NULL) {
    perror("malloc");
    exit(1);
  }
  {
    unsigned char *p = der;
    if (i2d_X509(crt, &p) < 0) {
      fprintf(stderr, "error: could not DER-encode certificate\n");
      exit(1);
    }
  }
  unsigned char digest[20];
  SHA1(der, derlen, digest);
  fprintf(stderr, "info: %s override for "
	  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
	  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x%s%s%s\n",
	  reason,
	  digest[0], digest[1], digest[2], digest[3], digest[4], 
	  digest[5], digest[6], digest[7], digest[8], digest[9], 
	  digest[10], digest[11], digest[12], digest[13], digest[14], 
	  digest[15], digest[16], digest[17], digest[18], digest[19], 
	  host ? " (host name \"" : "", host ? host : "", host ? "\")" : "");
  free(der);
}

/* If certificate host name checking fails, this function is called to
   implement an alternative matching, based on user overrides. */
static int
certificate_host_name_override(X509 *crt, const char *host)
{
  // Just a dummy implementation.  User overrides must be keyed both
  // by certificate (or its hash) and host name.
  if (getenv("CERT_OVERRIDE") != NULL) {
    info_certificate_override("host name", crt, host);
    return 1;
  }
  return 0;
}

/* If certificate validity checking fails, this function provides a
   second chance to accept the peer certificate.  If no user overrides
   are needed, this function can be removed. */
static int
certificate_validity_override(X509 *crt)
{
  // Just a dummy implementation for testing.  This should check a
  // user-maintained certificate store containing explicitly accepted
  // certificates.
  if (getenv("CERT_OVERRIDE") != NULL) {
    info_certificate_override("certificate validity", crt, NULL);
    return 1;
  }
  return 0;
}

static void __attribute__((noreturn))
failure(const char *msg)
{
  fprintf(stderr, "error: %s: %s\n", msg, strerror(errno));
  exit(2);
}

//+ Features TLS-OpenSSL-Errors
static void __attribute__((noreturn))
ssl_print_error_and_exit(SSL *ssl, const char *op, int ret)
{
  int subcode = SSL_get_error(ssl, ret);
  switch (subcode) {
  case SSL_ERROR_NONE:
    fprintf(stderr, "error: %s: no error to report\n", op);
    break;
  case SSL_ERROR_WANT_READ:
  case SSL_ERROR_WANT_WRITE:
  case SSL_ERROR_WANT_X509_LOOKUP:
  case SSL_ERROR_WANT_CONNECT:
  case SSL_ERROR_WANT_ACCEPT:
    fprintf(stderr, "error: %s: invalid blocking state %d\n", op, subcode);
    break;
  case SSL_ERROR_SSL:
    fprintf(stderr, "error: %s: TLS layer problem\n", op);
  case SSL_ERROR_SYSCALL:
    fprintf(stderr, "error: %s: system call failed: %s\n", op, strerror(errno));
    break;
  case SSL_ERROR_ZERO_RETURN:
    fprintf(stderr, "error: %s: zero return\n", op);
  }
  exit(1);
}
//-

int
main(int argc, char **argv)
{
  if (argc != 3) {
    usage(argv[0]);
  }

  BIO *bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
  if (bio_err == NULL) {
    perror("BIO_ne_fp(stderr)");
    exit(1);
  }

  //+ Features TLS-Client-OpenSSL-Init
  // The following call prints an error message and calls exit() if
  // the OpenSSL configuration file is unreadable.
  OPENSSL_config(NULL);
  // Provide human-readable error messages.
  SSL_load_error_strings();
  // Register ciphers.
  SSL_library_init();
  //-

  //+ Features TLS-Client-OpenSSL-CTX
  // Configure a client connection context.  Send a hendshake for the
  // highest supported TLS version, and disable compression.
  const SSL_METHOD *const req_method = SSLv23_client_method();
  SSL_CTX *const ctx = SSL_CTX_new(req_method);
  if (ctx == NULL) {
    ERR_print_errors(bio_err);
    exit(1);
  }
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION);

  // Adjust the ciphers list based on a whitelist.  First enable all
  // ciphers of at least medium strength, to get the list which is
  // compiled into OpenSSL.
  if (SSL_CTX_set_cipher_list(ctx, "HIGH:MEDIUM") != 1) {
    ERR_print_errors(bio_err);
    exit(1);
  }
  {
    // Create a dummy SSL session to obtain the cipher list.
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
      ERR_print_errors(bio_err);
      exit(1);
    }
    STACK_OF(SSL_CIPHER) *active_ciphers = SSL_get_ciphers(ssl);
    if (active_ciphers == NULL) {
      ERR_print_errors(bio_err);
      exit(1);
    }
    // Whitelist of candidate ciphers.
    static const char *const candidates[] =  {
      "AES128-GCM-SHA256", "AES128-SHA256", "AES256-SHA256", // strong ciphers
      "AES128-SHA", "AES256-SHA", // strong ciphers, also in older versions
      "RC4-SHA", "RC4-MD5", // backwards compatibility, supposed to be weak
      "DES-CBC3-SHA", "DES-CBC3-MD5", // more backwards compatibility
      NULL
    };
    // Actually selected ciphers.
    char ciphers[300];
    ciphers[0] = '\0';
    for (const char *const *c = candidates; *c; ++c) {
      for (int i = 0; i < sk_SSL_CIPHER_num(active_ciphers); ++i) {
	if (strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(active_ciphers, i)),
		   *c) == 0) {
	  if (*ciphers) {
	    strcat(ciphers, ":");
	  }
	  strcat(ciphers, *c);
	  break;
	}
      }
    }
    SSL_free(ssl);
    // Apply final cipher list.
    if (SSL_CTX_set_cipher_list(ctx, ciphers) != 1) {
      ERR_print_errors(bio_err);
      exit(1);
    }
  }

  // Load the set of trusted root certificates.
  if (!SSL_CTX_set_default_verify_paths(ctx)) {
    ERR_print_errors(bio_err);
    exit(1);
  }
  //-

  const char *host = argv[1];
  const char *service = argv[2];
  // Perform name lookup, create the TCP client socket, and connect to
  // the server.
  int sockfd = tcp_connect(host, service);
  if (sockfd < 0) {
    perror("connect");
    exit(1);
  }
  // Deactivate the Nagle algorithm.
  //+ Features TLS-Nagle
  const int val = 1;
  int ret = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
  if (ret < 0) {
    perror("setsockopt(TCP_NODELAY)");
    exit(1);
  }
  //-
  //+ Features TLS-Client-OpenSSL-Connect
  // Create the connection object.
  SSL *ssl = SSL_new(ctx);
  if (ssl == NULL) {
    ERR_print_errors(bio_err);
    exit(1);
  }
  SSL_set_fd(ssl, sockfd);

  // Enable the ServerNameIndication extension
  if (!SSL_set_tlsext_host_name(ssl, host)) {
    ERR_print_errors(bio_err);
    exit(1);
  }

  // Perform the TLS handshake with the server.
  ret = SSL_connect(ssl);
  if (ret != 1) {
    // Error status can be 0 or negative.
    ssl_print_error_and_exit(ssl, "SSL_connect", ret);
  }

  // Obtain the server certificate.
  X509 *peercert = SSL_get_peer_certificate(ssl);
  if (peercert == NULL) {
    fprintf(stderr, "peer certificate missing");
    exit(1);
  }

  // Check the certificate verification result.  Allow an explicit
  // certificate validation override in case verification fails.
  int verifystatus = SSL_get_verify_result(ssl);
  if (verifystatus != X509_V_OK && !certificate_validity_override(peercert)) {
    fprintf(stderr, "SSL_connect: verify result: %s\n",
	    X509_verify_cert_error_string(verifystatus));
    exit(1);
  }

  // Check if the server certificate matches the host name used to
  // establish the connection.
  // FIXME: Currently needs OpenSSL 1.1.
  if (X509_check_host(peercert, (const unsigned char *)host, strlen(host),
		      0) != 1
      && !certificate_host_name_override(peercert, host)) {
    fprintf(stderr, "SSL certificate does not match host name\n");
    exit(1);
  }

  X509_free(peercert);

  //-
  //+ Features TLS-Client-OpenSSL-Connection-Use
  const char *const req = "GET / HTTP/1.0\r\n\r\n";
  if (SSL_write(ssl, req, strlen(req)) < 0) {
    ssl_print_error_and_exit(ssl, "SSL_write", ret);
  }
  char buf[4096];
  ret = SSL_read(ssl, buf, sizeof(buf));
  if (ret < 0) {
    ssl_print_error_and_exit(ssl, "SSL_read", ret);
  }
  //-
  write(STDOUT_FILENO, buf, ret);
  //+ Features TLS-OpenSSL-Connection-Close
  // Send the close_notify alert.
  ret = SSL_shutdown(ssl);
  switch (ret) {
  case 1:
    // A close_notify alert has already been received.
    break;
  case 0:
    // Wait for the close_notify alert from the peer.
    ret = SSL_shutdown(ssl);
    switch (ret) {
    case 0:
      fprintf(stderr, "info: second SSL_shutdown returned zero\n");
      break;
    case 1:
      break;
    default:
      ssl_print_error_and_exit(ssl, "SSL_shutdown 2", ret);
    }
    break;
  default:
    ssl_print_error_and_exit(ssl, "SSL_shutdown 1", ret);
  }
  SSL_free(ssl);
  close(sockfd);
  //-
  //+ Features TLS-OpenSSL-Context-Close
  SSL_CTX_free(ctx);
  //-
  BIO_free(bio_err);
  return 0;
}

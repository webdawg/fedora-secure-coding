#include <assert.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>

#include "tcp_connect.h"

static void __attribute__((noreturn))
usage(const char *progname)
{
  fprintf(stderr, "usage: %s HOST PORT\n", progname);
  exit(2);
}

static void
info_certificate_override(const char *reason,
			  const gnutls_datum_t cert, const char *host)
{
#ifdef HAVE_GNUTLS_HASH_FAST
  unsigned char digest[20];
  assert(gnutls_hash_get_len(GNUTLS_DIG_SHA1) == sizeof(digest));
  int ret = gnutls_hash_fast(GNUTLS_DIG_SHA1,
			     cert.data, cert.size, digest);
  if (ret < 0) {
    fprintf(stderr, "error: SHA1 digest failed: %s\n", gnutls_strerror(ret));
    exit(1);
  }
  fprintf(stderr, "info: %s override for "
	  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
	  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x%s%s%s\n",
	  reason,
	  digest[0], digest[1], digest[2], digest[3], digest[4], 
	  digest[5], digest[6], digest[7], digest[8], digest[9], 
	  digest[10], digest[11], digest[12], digest[13], digest[14], 
	  digest[15], digest[16], digest[17], digest[18], digest[19], 
	  host ? " (host name \"" : "", host ? host : "", host ? "\")" : "");
#endif
}

/* If certificate host name checking fails, this function is called to
   implement an alternative matching, based on user overrides. */
static int
certificate_host_name_override(const gnutls_datum_t cert, const char *host)
{
  // Just a dummy implementation.  User overrides must be keyed both
  // by certificate (or its hash) and host name.
  if (getenv("CERT_OVERRIDE") != NULL) {
    info_certificate_override("host name", cert, host);
    return 1;
  }
  return 0;
}

/* If certificate validity checking fails, this function provides a
   second chance to accept the peer certificate.  If no user overrides
   are needed, this function can be removed. */
static int
certificate_validity_override(const gnutls_datum_t cert)
{
  // Just a dummy implementation for testing.  This should check a
  // user-maintained certificate store containing explicitly accepted
  // certificates.
  if (getenv("CERT_OVERRIDE") != NULL) {
    info_certificate_override("certificate validity", cert, NULL);
    return 1;
  }
  return 0;
}

int
main(int argc, char **argv)
{
  if (argc != 3) {
    usage(argv[0]);
  }

  //+ Features TLS-GNUTLS-Init
  gnutls_global_init();
  //-

  //+ Features TLS-Client-GNUTLS-Credentials
  // Load the trusted CA certificates.
  gnutls_certificate_credentials_t cred = NULL;
  int ret = gnutls_certificate_allocate_credentials (&cred);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "error: gnutls_certificate_allocate_credentials: %s\n",
	    gnutls_strerror(ret));
    exit(1);
  }
  // gnutls_certificate_set_x509_system_trust needs GNUTLS version 3.0
  // or newer, so we hard-code the path to the certificate store
  // instead.
  static const char ca_bundle[] = "/etc/ssl/certs/ca-bundle.crt";
  ret = gnutls_certificate_set_x509_trust_file
    (cred, ca_bundle, GNUTLS_X509_FMT_PEM);
  if (ret == 0) {
    fprintf(stderr, "error: no certificates found in: %s\n", ca_bundle);
    exit(1);
  }
  if (ret < 0) {
    fprintf(stderr, "error: gnutls_certificate_set_x509_trust_files(%s): %s\n",
	    ca_bundle, gnutls_strerror(ret));
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
  {
    const int val = 1;
    int ret = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
    if (ret < 0) {
      perror("setsockopt(TCP_NODELAY)");
      exit(1);
    }
  }

  //+ Features TLS-Client-GNUTLS-Connect
  // Create the session object.
  gnutls_session_t session;
  ret = gnutls_init(&session, GNUTLS_CLIENT);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "error: gnutls_init: %s\n",
	    gnutls_strerror(ret));
    exit(1);
  }

  // Configure the cipher preferences.
  const char *errptr = NULL;
  ret = gnutls_priority_set_direct(session, "NORMAL", &errptr);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "error: gnutls_priority_set_direct: %s\n"
	    "error: at: \"%s\"\n", gnutls_strerror(ret), errptr);
    exit(1);
  }

  // Install the trusted certificates.
  ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "error: gnutls_credentials_set: %s\n",
	    gnutls_strerror(ret));
    exit(1);
  }

  // Associate the socket with the session object and set the server
  // name.
  gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)(uintptr_t)sockfd);
  ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS,
			       host, strlen(host));
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "error: gnutls_server_name_set: %s\n",
	    gnutls_strerror(ret));
    exit(1);
  }

  // Establish the session.
  ret = gnutls_handshake(session);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "error: gnutls_handshake: %s\n",
	    gnutls_strerror(ret));
    exit(1);
  }
  //-

  //+ Features TLS-Client-GNUTLS-Verify
  // Obtain the server certificate chain.  The server certificate
  // itself is stored in the first element of the array.
  unsigned certslen = 0;
  const gnutls_datum_t *const certs =
    gnutls_certificate_get_peers(session, &certslen);
  if (certs == NULL || certslen == 0) {
    fprintf(stderr, "error: could not obtain peer certificate\n");
    exit(1);
  }

  // Validate the certificate chain.
  unsigned status = (unsigned)-1;
  ret = gnutls_certificate_verify_peers2(session, &status);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "error: gnutls_certificate_verify_peers2: %s\n",
	    gnutls_strerror(ret));
    exit(1);
  }
  if (status != 0 && !certificate_validity_override(certs[0])) {
    gnutls_datum_t msg;
#if GNUTLS_VERSION_AT_LEAST_3_1_4
    int type = gnutls_certificate_type_get (session);
    ret = gnutls_certificate_verification_status_print(status, type, &out, 0);
#else
    ret = -1;
#endif
    if (ret == 0) {
      fprintf(stderr, "error: %s\n", msg.data);
      gnutls_free(msg.data);
      exit(1);
    } else {
      fprintf(stderr, "error: certificate validation failed with code 0x%x\n",
	      status);
      exit(1);
    }
  }
  //-

  //+ Features TLS-Client-GNUTLS-Match
  // Match the peer certificate against the host name.
  // We can only obtain a set of DER-encoded certificates from the
  // session object, so we have to re-parse the peer certificate into
  // a certificate object.
  gnutls_x509_crt_t cert;
  ret = gnutls_x509_crt_init(&cert);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "error: gnutls_x509_crt_init: %s\n",
	    gnutls_strerror(ret));
    exit(1);
  }
  // The peer certificate is the first certificate in the list.
  ret = gnutls_x509_crt_import(cert, certs, GNUTLS_X509_FMT_DER);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "error: gnutls_x509_crt_import: %s\n",
	    gnutls_strerror(ret));
    exit(1);
  }
  ret = gnutls_x509_crt_check_hostname(cert, host);
  if (ret == 0 && !certificate_host_name_override(certs[0], host)) {
    fprintf(stderr, "error: host name does not match certificate\n");
    exit(1);
  }
  gnutls_x509_crt_deinit(cert);
  //-

  //+ Features TLS-GNUTLS-Use
  char buf[4096];
  snprintf(buf, sizeof(buf), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host);
  ret = gnutls_record_send(session, buf, strlen(buf));
  if (ret < 0) {
    fprintf(stderr, "error: gnutls_record_send: %s\n", gnutls_strerror(ret));
    exit(1);
  }
  ret = gnutls_record_recv(session, buf, sizeof(buf));
  if (ret < 0) {
    fprintf(stderr, "error: gnutls_record_recv: %s\n", gnutls_strerror(ret));
    exit(1);
  }
  //-
  write(STDOUT_FILENO, buf, ret);

  //+ Features TLS-GNUTLS-Disconnect
  // Initiate an orderly connection shutdown.
  ret = gnutls_bye(session, GNUTLS_SHUT_RDWR);
  if (ret < 0) {
    fprintf(stderr, "error: gnutls_bye: %s\n", gnutls_strerror(ret));
    exit(1);
  }
  // Free the session object.
  gnutls_deinit(session);
  //-

  //+ Features TLS-GNUTLS-Credentials-Close
  gnutls_certificate_free_credentials(cred);
  //-
}

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "tcp_connect.h"

//+ Features TLS-NSS-Includes
// NSPR include files
#include <prerror.h>
#include <prinit.h>

// NSS include files
#include <nss.h>
#include <pk11pub.h>
#include <secmod.h>
#include <ssl.h>
#include <sslproto.h>

// Private API, no other way to turn a POSIX file descriptor into an
// NSPR handle.
NSPR_API(PRFileDesc*) PR_ImportTCPSocket(int);
//-

static void __attribute__((noreturn))
usage(const char *progname)
{
  fprintf(stderr, "usage: %s HOST PORT\n", progname);
  exit(2);
}

SECStatus
bad_certificate(void *arg, PRFileDesc *fd)
{
  const char *host = arg;
  CERTCertificate *cert = SSL_PeerCertificate(fd);
  if (cert == NULL) {
    return SECFailure;
  }

  // Just a dummy implementation.  User overrides must be keyed both
  // by certificate (or its hash) and host name.
  if (getenv("CERT_OVERRIDE") != NULL) {
    unsigned char sha1[20];
    if (PK11_HashBuf(SEC_OID_SHA1, sha1, 
		     cert->derCert.data, cert->derCert.len) != SECSuccess) {
      fprintf(stderr, "error: could not hash certificate\n");
      return SECFailure;
    }
    SECItem si = {.data = sha1, .len = sizeof(sha1)};
    char *hex = CERT_Hexify(&si, 1);
    if (hex == NULL) {
      fprintf(stderr, "error: could not hash certificate\n");
      return SECFailure;
    }
    fprintf(stderr, "info: certificate override for %s (host name %s)\n",
	    hex, host);
    PORT_Free(hex);
    CERT_DestroyCertificate(cert);
    return SECSuccess;
  }
  CERT_DestroyCertificate(cert);
  return SECFailure;
}

int
main(int argc, char **argv)
{
  if (argc != 3) {
    usage(argv[0]);
  }

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

  //+ Features TLS-NSS-Init
  PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
  NSSInitContext *const ctx =
    NSS_InitContext("sql:/etc/pki/nssdb", "", "", "", NULL,
		    NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);
  if (ctx == NULL) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: NSPR error code %d: %s\n",
	    err, PR_ErrorToName(err));
    exit(1);
  }

  // Ciphers to enable.
  static const PRUint16 good_ciphers[] = {
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,
    SSL_NULL_WITH_NULL_NULL // sentinel
  };

  // Check if the current policy allows any strong ciphers.  If it
  // doesn't, switch to the "domestic" (unrestricted) policy.  This is
  // not thread-safe and has global impact.  Consequently, we only do
  // it if absolutely necessary.
  int found_good_cipher = 0;
  for (const PRUint16 *p = good_ciphers; *p != SSL_NULL_WITH_NULL_NULL;
       ++p) {
    PRInt32 policy;
    if (SSL_CipherPolicyGet(*p, &policy) != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      fprintf(stderr, "error: policy for cipher %u: error %d: %s\n",
	      (unsigned)*p, err, PR_ErrorToName(err));
      exit(1);
    }
    if (policy == SSL_ALLOWED) {
      fprintf(stderr, "info: found cipher %x\n", (unsigned)*p);
      found_good_cipher = 1;
      break;
    }
  }
  if (!found_good_cipher) {
    if (NSS_SetDomesticPolicy() != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      fprintf(stderr, "error: NSS_SetDomesticPolicy: error %d: %s\n",
	      err, PR_ErrorToName(err));
      exit(1);
    }
  }

  // Initialize the trusted certificate store.
  char module_name[] = "library=libnssckbi.so name=\"Root Certs\"";
  SECMODModule *module = SECMOD_LoadUserModule(module_name, NULL, PR_FALSE);
  if (module == NULL || !module->loaded) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: NSPR error code %d: %s\n",
	    err, PR_ErrorToName(err));
    exit(1);
  }
  //-

  //+ Features TLS-Client-NSS-Connect
  // Wrap the POSIX file descriptor.  This is an internal NSPR
  // function, but it is very unlikely to change.
  PRFileDesc* nspr = PR_ImportTCPSocket(sockfd);
  sockfd = -1; // Has been taken over by NSPR.

  // Add the SSL layer.
  {
    PRFileDesc *model = PR_NewTCPSocket();
    PRFileDesc *newfd = SSL_ImportFD(NULL, model);
    if (newfd == NULL) {
      const PRErrorCode err = PR_GetError();
      fprintf(stderr, "error: NSPR error code %d: %s\n",
	      err, PR_ErrorToName(err));
      exit(1);
    }
    model = newfd;
    newfd = NULL;
    if (SSL_OptionSet(model, SSL_ENABLE_SSL2, PR_FALSE) != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      fprintf(stderr, "error: set SSL_ENABLE_SSL2 error %d: %s\n",
	      err, PR_ErrorToName(err));
      exit(1);
    }
    if (SSL_OptionSet(model, SSL_V2_COMPATIBLE_HELLO, PR_FALSE) != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      fprintf(stderr, "error: set SSL_V2_COMPATIBLE_HELLO error %d: %s\n",
	      err, PR_ErrorToName(err));
      exit(1);
    }
    if (SSL_OptionSet(model, SSL_ENABLE_DEFLATE, PR_FALSE) != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      fprintf(stderr, "error: set SSL_ENABLE_DEFLATE error %d: %s\n",
	      err, PR_ErrorToName(err));
      exit(1);
    }

    // Disable all ciphers (except RC4-based ciphers, for backwards
    // compatibility).
    const PRUint16 *const ciphers = SSL_GetImplementedCiphers();
    for (unsigned i = 0; i < SSL_GetNumImplementedCiphers(); i++) {
      if (ciphers[i] != SSL_RSA_WITH_RC4_128_SHA
	  && ciphers[i] != SSL_RSA_WITH_RC4_128_MD5) {
	if (SSL_CipherPrefSet(model, ciphers[i], PR_FALSE) != SECSuccess) {
	  const PRErrorCode err = PR_GetError();
	  fprintf(stderr, "error: disable cipher %u: error %d: %s\n",
		  (unsigned)ciphers[i], err, PR_ErrorToName(err));
	  exit(1);
	}
      }
    }

    // Enable the strong ciphers.
    for (const PRUint16 *p = good_ciphers; *p != SSL_NULL_WITH_NULL_NULL;
	 ++p) {
      if (SSL_CipherPrefSet(model, *p, PR_TRUE) != SECSuccess) {
	const PRErrorCode err = PR_GetError();
	fprintf(stderr, "error: enable cipher %u: error %d: %s\n",
		(unsigned)*p, err, PR_ErrorToName(err));
	exit(1);
      }
    }

    // Allow overriding invalid certificate.
    if (SSL_BadCertHook(model, bad_certificate, (char *)host) != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      fprintf(stderr, "error: SSL_BadCertHook error %d: %s\n",
	      err, PR_ErrorToName(err));
      exit(1);
    }

    newfd = SSL_ImportFD(model, nspr);
    if (newfd == NULL) {
      const PRErrorCode err = PR_GetError();
      fprintf(stderr, "error: SSL_ImportFD error %d: %s\n",
	      err, PR_ErrorToName(err));
      exit(1);
    }
    nspr = newfd;
    PR_Close(model);
  }

  // Perform the handshake.
  if (SSL_ResetHandshake(nspr, PR_FALSE) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: SSL_ResetHandshake error %d: %s\n",
	    err, PR_ErrorToName(err));
    exit(1);
  }
  if (SSL_SetURL(nspr, host) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: SSL_SetURL error %d: %s\n",
	    err, PR_ErrorToName(err));
    exit(1);
  }
  if (SSL_ForceHandshake(nspr) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: SSL_ForceHandshake error %d: %s\n",
	    err, PR_ErrorToName(err));
    exit(1);
  }
  //-

  //+ Features TLS-NSS-Use
  char buf[4096];
  snprintf(buf, sizeof(buf), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host);
  PRInt32 ret = PR_Write(nspr, buf, strlen(buf));
  if (ret < 0) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: PR_Write error %d: %s\n",
	    err, PR_ErrorToName(err));
    exit(1);
  }
  ret = PR_Read(nspr, buf, sizeof(buf));
  if (ret < 0) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: PR_Read error %d: %s\n",
	    err, PR_ErrorToName(err));
    exit(1);
  }
  //-
  write(STDOUT_FILENO, buf, ret);

  //+ Features TLS-Client-NSS-Close
  // Send close_notify alert.
  if (PR_Shutdown(nspr, PR_SHUTDOWN_BOTH) != PR_SUCCESS) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: PR_Read error %d: %s\n",
	    err, PR_ErrorToName(err));
    exit(1);
  }
  // Closes the underlying POSIX file descriptor, too.
  PR_Close(nspr);
  //-

  //+ Features TLS-NSS-Close
  SECMOD_DestroyModule(module);
  NSS_ShutdownContext(ctx);
  //-

  return 0;
}

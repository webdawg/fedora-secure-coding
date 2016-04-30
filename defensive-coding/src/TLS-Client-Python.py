#!/usr/bin/python

# WARNING: See the guidelines for problems with this code!

import socket
import ssl
import sys

_, host, port = sys.argv

#+ Features TLS-Client-Python-check_host_name
def check_host_name(peercert, name):
    """Simple certificate/host name checker.  Returns True if the
    certificate matches, False otherwise.  Does not support
    wildcards."""
    # Check that the peer has supplied a certificate.
    # None/{} is not acceptable.
    if not peercert:
        return False
    if peercert.has_key("subjectAltName"):
        for typ, val in peercert["subjectAltName"]:
            if typ == "DNS" and val == name:
                return True
    else:
        # Only check the subject DN if there is no subject alternative
        # name.
        cn = None
        for attr, val in peercert["subject"][0]:
            # Use most-specific (last) commonName attribute.
            if attr == "commonName":
                cn = val
        if cn is not None:
            return cn == name
    return False
#-              

# WARNING: See the guidelines for problems with this code!

sock = socket.create_connection((host, port))
#+ Features TLS-Client-Python-Connect
sock = ssl.wrap_socket(sock,
                       ciphers="HIGH:-aNULL:-eNULL:-PSK:RC4-SHA:RC4-MD5",
                       ssl_version=ssl.PROTOCOL_TLSv1,
                       cert_reqs=ssl.CERT_REQUIRED,
                       ca_certs='/etc/ssl/certs/ca-bundle.crt')
# getpeercert() triggers the handshake as a side effect.
if not check_host_name(sock.getpeercert(), host):
    raise IOError("peer certificate does not match host name")
#-
#+ Features TLS-Python-Use
sock.write("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
print sock.read()
#-
#+ Features TLS-Python-Close
sock.close()
#-

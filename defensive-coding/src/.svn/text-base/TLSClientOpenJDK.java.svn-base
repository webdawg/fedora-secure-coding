//+ Features TLS-Client-OpenJDK-Import
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import sun.security.util.HostnameChecker;
//-

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.ArrayList;
import java.nio.charset.Charset;

public class TLSClientOpenJDK {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
        }
        int index = 0;
        byte[] certHash = null;
        if (args[index].equals("--accept")) {
            ++index;
            if (args.length != 4) {
                usage();
            }
            certHash = decodeHex(args[index++]);
        } else if (args.length != 2) {
            usage();
        }
        
        String host = args[index++];
        int port;
        try {
            port = Integer.parseInt(args[index]);
        } catch (NumberFormatException e) {
            port = 0;
        }
        if (port <= 0 || port > 65535) {
            usage();
        }

        SSLContext ctx;
        if (certHash == null) {
            ctx = createContext();
        } else {
            ctx = createContextForCertificate(certHash);
        }
        
        SSLParameters params = createParameters(ctx);
        if (certHash == null) {
            params.setEndpointIdentificationAlgorithm(null);
        }
        runDemo(ctx, params, host, port);
    }

    private static SSLContext createContext()  throws Exception {
        //+ Features TLS-Client-OpenJDK-Context
        // Create the context.  Specify the SunJSSE provider to avoid
        // picking up third-party providers.  Try the TLS 1.2 provider
        // first, then fall back to TLS 1.0.
        SSLContext ctx;
        try {
            ctx = SSLContext.getInstance("TLSv1.2", "SunJSSE");
        } catch (NoSuchAlgorithmException e) {
            try {
                ctx = SSLContext.getInstance("TLSv1", "SunJSSE");
            } catch (NoSuchAlgorithmException e1) {
                // The TLS 1.0 provider should always be available.
                throw new AssertionError(e1);
            } catch (NoSuchProviderException e1) {
                throw new AssertionError(e1);
            } 
        } catch (NoSuchProviderException e) {
            // The SunJSSE provider should always be available.
            throw new AssertionError(e);
        }
        ctx.init(null, null, null);
        //-
        return ctx;
    }
    
    static
    //+ Features TLS-Client-OpenJDK-MyTrustManager
    public class MyTrustManager implements X509TrustManager {
        private final byte[] certHash;

        public MyTrustManager(byte[] certHash) throws Exception {
            this.certHash = certHash;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain,
                String authType) throws CertificateException {
            byte[] digest = getCertificateDigest(chain[0]);
            String digestHex = formatHex(digest);

            if (Arrays.equals(digest, certHash)) {
                System.err.println("info: accepting certificate: " + digestHex);
            } else {
                throw new CertificateException("certificate rejected: "  +
                        digestHex);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
    //-

    private static SSLContext createContextForCertificate(byte[] certHash)
            throws Exception {
        //+ Features TLS-Client-OpenJDK-Context_For_Cert
        SSLContext ctx;
        try {
            ctx = SSLContext.getInstance("TLSv1.2", "SunJSSE");
        } catch (NoSuchAlgorithmException e) {
            try {
                ctx = SSLContext.getInstance("TLSv1", "SunJSSE");
            } catch (NoSuchAlgorithmException e1) {
                throw new AssertionError(e1);
            } catch (NoSuchProviderException e1) {
                throw new AssertionError(e1);
            }
        } catch (NoSuchProviderException e) {
            throw new AssertionError(e);
        }
        MyTrustManager tm = new MyTrustManager(certHash);
        ctx.init(null, new TrustManager[] {tm}, null);
        //-
        return ctx;
    }
    
    private static SSLParameters createParameters(SSLContext ctx)
        throws Exception {
        //+ Features TLS-OpenJDK-Parameters
        // Prepare TLS parameters.  These have to applied to every TLS
        // socket before the handshake is triggered.
        SSLParameters params = ctx.getDefaultSSLParameters();
        // Do not send an SSL-2.0-compatible Client Hello.
        ArrayList<String> protocols = new ArrayList<String>(
            Arrays.asList(params.getProtocols()));
        protocols.remove("SSLv2Hello");
        params.setProtocols(protocols.toArray(new String[protocols.size()]));
        // Adjust the supported ciphers.
        ArrayList<String> ciphers = new ArrayList<String>(
            Arrays.asList(params.getCipherSuites()));
        ciphers.retainAll(Arrays.asList(
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
            "SSL_RSA_WITH_RC4_128_SHA1",
            "SSL_RSA_WITH_RC4_128_MD5",
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"));
        params.setCipherSuites(ciphers.toArray(new String[ciphers.size()]));
        //-
        // Activate host name verification.  Requires OpenJDK 7.
        //+ Features TLS-Client-OpenJDK-Hostname
        params.setEndpointIdentificationAlgorithm("HTTPS");
        //-
        return params;
    }

    private static void runDemo(SSLContext ctx, SSLParameters params,
            String host, int port) throws Exception {
        // Note: The code below misses the close() call, to avoid
        // messing up the indentation in the generated documentation.

        //+ Features TLS-Client-OpenJDK-Connect
        // Create the socket and connect it at the TCP layer.
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory()
            .createSocket(host, port);

        // Disable the Nagle algorithm.
        socket.setTcpNoDelay(true);

        // Adjust ciphers and protocols.
        socket.setSSLParameters(params);

        // Perform the handshake.
        socket.startHandshake();

        // Validate the host name.  The match() method throws
        // CertificateException on failure.
        X509Certificate peer = (X509Certificate)
            socket.getSession().getPeerCertificates()[0];
        // This is the only way to perform host name checking on OpenJDK 6.
        HostnameChecker.getInstance(HostnameChecker.TYPE_TLS).match(
            host, peer);
        //-

        //+ Features TLS-Client-OpenJDK-Use
        socket.getOutputStream().write("GET / HTTP/1.0\r\n\r\n"
            .getBytes(Charset.forName("UTF-8")));
        byte[] buffer = new byte[4096];
        int count = socket.getInputStream().read(buffer);
        System.out.write(buffer, 0, count);
        //-
    }
    
    private static byte[] decodeHex(String s) {
        byte[] result = new byte[32];
        if (s.length() != result.length * 2) {
            throw new IllegalArgumentException(s);
        }
        for (int i = 0; i < result.length; ++i) {
            int a = Character.digit(s.charAt(2 * i), 16);
            int b = Character.digit(s.charAt(2 * i + 1), 16);
            if (a < 0 || b < 0) {
                throw new IllegalArgumentException(s);
            }
            result[i] = (byte) ((a << 4) | b);
        }
        return result;
    }

    private static String formatHex(byte[] digest) {
        String digestHex;
        {
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            digestHex = sb.toString();
        }
        return digestHex;
    }
    
    private static byte[] getCertificateDigest(X509Certificate chain)
            throws AssertionError, CertificateEncodingException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e1) {
            throw new AssertionError(e1);
        }
        byte[] digest = md.digest(chain.getEncoded());
        return digest;
    }

    private static void usage() {
        System.err.format("usage: %s [--accept CERT-HASH] HOST PORT%n",
                          TLSClientOpenJDK.class.getName());
        System.exit(1);
    }
}

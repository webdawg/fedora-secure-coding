import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Minimalistic DER parser suitable for extracting the commonName attribute from
 * a subject distinguished name of an X.509 certificate.
 * 
 * <p>
 * All elements in the DER structure can be parsed using:
 * 
 * <pre>
 * while (parser.isRemaining()) {
 *     if (!parser.next()) {
 *         handleError();
 *         break;
 *     }
 *     // Examine parser.getTagClass() etc. here.
 * }
 * </pre>
 * <p>
 * Note that this parser only handles structures of up to 16 MB in size.
 * 
 * @author Florian Weimer <fweimer@redhat.com>
 * 
 */
public final class DERParser {
    private final byte[] data;
    private final int end;
    private int offset;

    private int tag = -1;
    private int contentLength = -1;

    // Content starts at offset - contentLength.

    /**
     * Creates a new parser for the specified array.
     * 
     * @param data
     *            the data to parse (not copied)
     * @throws NullPointerException
     *             the argument is null
     */
    public DERParser(byte[] data) {
        this(data, 0, data.length);
    }

    /**
     * Creates an new parser for the slice [offset, offset + length) of the byte
     * array.
     * 
     * @param data
     *            the array to parse from (not copied)
     * @param offset
     *            the offset at which to start parsing
     * @param length
     *            the number of bytes to parse
     * @throws NullPointerException
     *             the array argument is null
     * @throws ArrayIndexOutOfBoundsException
     *             offset or length are negative or extend past the end of the
     *             array
     */
    public DERParser(byte[] data, int offset, int length) {
        this.data = data;
        this.offset = offset;
        end = offset + length;
        if (offset < 0 || length < 0 || offset > data.length || end < 0
                || end > data.length)
            throw new ArrayIndexOutOfBoundsException();
    }

    /**
     * Returns true if more data can be extracted from the input.
     */
    public boolean isRemaining() {
        return offset < end;
    }

    /**
     * Decodes the next tag/length/value element in the input data. After that,
     * the parsed data can be examined using
     * {@link #getTag()}, {@link #getLength()}, {@link #getString()}, and
     * {@link #open()}.
     * @return true if the TLV could be parsed successfully, false otherwise
     */
    public boolean next() {
        if (offset >= end)
            throw new IllegalStateException("input exhausted");
        int identifier = data[offset];
        tag = identifier & ~0x20; // mask out P/C bit
        if ((tag & 0x1f) == 31)
            return false; // long form of type not supported
        ++offset;
        if (offset >= end)
            return false;
        contentLength = data[offset];
        if (contentLength < 0) {
            int subLength = contentLength & 0x7f;
            contentLength = 0;
            switch (subLength) {
            case 3:
                ++offset;
                if (offset >= end)
                    return false;
                contentLength = (data[offset] & 0xFF) << 16;
                //$FALL-THROUGH$
            case 2:
                ++offset;
                if (offset >= end)
                    return false;
                contentLength = contentLength | ((data[offset] & 0xFF) << 8);
                //$FALL-THROUGH$
            case 1:
                ++offset;
                if (offset >= end)
                    return false;
                contentLength = contentLength | (data[offset] & 0xFF);
                break;
            case 0:
            default:
                // We only need to support DER values up to 16 MB.
                return false;
            }
        }
        ++offset;
        if (offset + contentLength < 0 || offset + contentLength > end)
            return false;
        offset += contentLength;
        return true;
    }

    public static final int TAG_OBJECT_IDENTIFIER = 6;
    public static final int TAG_UTF8_STRING = 12;
    public static final int TAG_SEQUENCE = 16;
    public static final int TAG_SET = 17;
    public static final int TAG_PRINTABLE_STRING = 19;
    public static final int TAG_TELETEX_STRING = 20;
    public static final int TAG_IA5_STRING = 22;
    public static final int TAG_UNIVERSAL_STRING = 28;
    public static final int TAG_BMP_STRING = 30;

    /**
     * Returns the tag value encountered by the most recent call to
     * {@link #next()}.
     * @return if the class is universal, an integer between 0 and 31,
     *   otherwise a positive integer less than 255 (which includes
     *   the class bits as well)
     */
    public int getTag() {
        return tag;
    }

    /**
     * Returns the length (in bytes) of the content encountered by the most
     * recent call to {@link #next()}.
     * 
     * @return a non-negative integer
     */
    public int getLength() {
        return contentLength;
    }

    /**
     * Returns true if the current content bytes are equal to the specified
     * bytes.
     * 
     * @param reference
     *            the byte array to compare the current content to
     * @return true if length the byte content match
     */
    public boolean isContent(byte[] reference) {
        if (reference.length != contentLength)
            return false;
        int off = offset - contentLength;
        for (int i = 0; i < reference.length; ++i) {
            if (data[off + i] != reference[i])
                return false;
        }
        return true;
    }

    /**
     * Returns the current object as a string.
     * 
     * @return a new string which contains the current content in decoded form
     * @throws IllegalStateException
     *             the parser is not positioned at a string type
     */
    public String getString() {
        String charset;
        switch (tag) {
        case TAG_UTF8_STRING:
            charset = "UTF-8";
            break;
        case TAG_PRINTABLE_STRING:
        case TAG_TELETEX_STRING: // ASCII super-set not supported by Java
        case TAG_IA5_STRING:
            charset = "ASCII";
            break;
        case TAG_UNIVERSAL_STRING:
            charset = "UTF-32BE";
            break;
        case TAG_BMP_STRING:
            charset = "UTF-16BE";
            break;
        default:
            throw new IllegalStateException(
                    "string requested for non-string type " + tag);
        }
        return new String(data, offset - contentLength, contentLength,
                Charset.forName(charset));
    }

    /**
     * Returns a DER parser for the current substructure
     * 
     * @return a new DER parser object which shares the underlying byte array
     *         with this one
     */
    public DERParser open() {
        return new DERParser(data, offset - contentLength, contentLength);
    }

    // Code below only included for exploratory purposes.

    private static final byte[] OID_COMMON_NAME = { 2 * 40 + 5, 4, 3 };

    public static String getHostname(X509Certificate peer) {
        DERParser outer = new DERParser(peer.getSubjectX500Principal()
                .getEncoded());
        if (!outer.next() || outer.getTag() != DERParser.TAG_SEQUENCE)
	    return null;
        outer = outer.open();
        String mostSpecificCN = null;
        while (outer.isRemaining()) {
            if (!outer.next() || outer.getTag() != DERParser.TAG_SET)
		return null;
            DERParser inner = outer.open();
            if (!inner.next() || inner.getTag() != DERParser.TAG_SEQUENCE)
		continue;
            inner = inner.open();
            if (inner.next() && inner.getTag() == TAG_OBJECT_IDENTIFIER
                    && inner.isContent(OID_COMMON_NAME)) {
                inner.next(); // read value
                try {
                    mostSpecificCN = inner.getString();
                } catch (IllegalArgumentException e) {
                    // Ignore unsupported string types.
                }
            }
        }
        return mostSpecificCN;
    }
    
    public static void main(String[] args) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (String arg : args) {
            InputStream in = new BufferedInputStream(
                    new FileInputStream(arg));
            try {
                X509Certificate cert =
                        (X509Certificate) factory.generateCertificate(in);
                System.out.format("%s: %s%n", arg, getHostname(cert));
            } finally {
                in.close();
            }
        }
    }
}

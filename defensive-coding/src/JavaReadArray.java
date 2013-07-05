import java.io.EOFException;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;

import java.util.Arrays;

public class JavaReadArray {
    public static void main(String[] args) throws IOException {
	String path = args[0];
	int length = Integer.parseInt(args[1]);

	byte[] data;
	try (InputStream in = new FileInputStream(path)) {
	    data = readBytes(in, length);
        }
	System.out.write(data);
    }

    //+ Java Language-ReadArray
    static byte[] readBytes(InputStream in, int length) throws IOException {
	final int startSize = 65536;
        byte[] b = new byte[Math.min(length, startSize)];
        int filled = 0;
        while (true) {
            int remaining = b.length - filled;
	    readFully(in, b, filled, remaining);
            if (b.length == length) {
                break;
            }
            filled = b.length;
            if (length - b.length <= b.length) {
                // Allocate final length.  Condition avoids overflow.
                b = Arrays.copyOf(b, length);
            } else {
                b = Arrays.copyOf(b, b.length * 2);
            }
        }
        return b;
    }

    static void readFully(InputStream in,byte[] b, int off, int len)
	    throws IOException {
	int startlen = len;
        while (len > 0) {
            int count = in.read(b, off, len);
            if (count < 0) {
                throw new EOFException();
            }
            off += count;
            len -= count;
        }
    }
    //-
}

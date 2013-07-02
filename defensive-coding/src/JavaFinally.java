import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public abstract class JavaFinally {
    File path;

    abstract void readFile(InputStream in) throws Exception;

    void finallyExample() throws Exception {
	//+ Java Finally
	InputStream in = new BufferedInputStream(new FileInputStream(path));
	try {
	    readFile(in);
	} finally {
	    in.close();
	}
	//-
    }

    void tryWithResource() throws Exception {
	//+ Java TryWithResource
	try (InputStream in = new BufferedInputStream(new FileInputStream(path))) {
	    readFile(in);
	}
	//-
    }

    static native int sum(byte[] buffer, int offset, int length);
}

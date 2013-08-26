// Test with:
//
//     java  -Djava.security.manager \
//       -Djava.security.policy=data/java/grant-all.policy \
//       JavaSecurityManagerUnprivileged JavaFinally.java {true|false}

import java.io.FileInputStream;
import java.io.FilePermission;
import java.io.IOException;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Permissions;
import java.security.PrivilegedExceptionAction;
import java.security.ProtectionDomain;

public class JavaSecurityManagerUnprivileged {
    public static void main(String[] args) throws Exception {
	final String path = args[0];
	boolean grant = Boolean.parseBoolean(args[1]);
	if (grant) {
	    withGrant(path);
	    return;
	}

	//+ Java SecurityManager-Unprivileged
	Permissions permissions = new Permissions();
        ProtectionDomain protectionDomain =
	    new ProtectionDomain(null, permissions);
        AccessControlContext context = new AccessControlContext(
            new ProtectionDomain[] { protectionDomain });

	// This is expected to succeed.
	try (FileInputStream in = new FileInputStream(path)) {
	    System.out.format("FileInputStream: %s%n", in);
	}

	AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
		@Override
	        public Void run() throws Exception {
		    // This code runs with reduced privileges and is
		    // expected to fail.
		    try (FileInputStream in = new FileInputStream(path)) {
			System.out.format("FileInputStream: %s%n", in);
		    }
		    return null;
		}
	    }, context);
	//-
    }

    private static void withGrant(final String path) throws Exception {
	Permissions permissions = new Permissions();
	//+ Java SecurityManager-CurrentDirectory
	permissions.add(new FilePermission(
            System.getProperty("user.dir") + "/-", "read"));
	//-
        ProtectionDomain protectionDomain =
	    new ProtectionDomain(null, permissions);
        AccessControlContext context = new AccessControlContext(
            new ProtectionDomain[] { protectionDomain });

	// This is expected to succeed.
	try (FileInputStream in = new FileInputStream(path)) {
	    System.out.format("FileInputStream: %s%n", in);
	}

	AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
		@Override
	        public Void run() throws Exception {
		    // This code runs with reduced privileges and is
		    // expected to fail.
		    try (FileInputStream in = new FileInputStream(path)) {
			System.out.format("FileInputStream: %s%n", in);
			return null;
		    }
		}
	    }, context);
    }
}

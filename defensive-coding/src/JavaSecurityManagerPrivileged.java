// Test with:
//
//     java  -Djava.security.manager \
//       JavaSecurityManagerPrivileged

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Permissions;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;

public class JavaSecurityManagerPrivileged {
    public static void main(String[] args) throws Exception {
        Permissions permissions = new Permissions();
        ProtectionDomain protectionDomain =
            new ProtectionDomain(null, permissions);
        AccessControlContext context = new AccessControlContext(
            new ProtectionDomain[] { protectionDomain });

        AccessController.doPrivileged(new PrivilegedAction<Void>() {
                @Override
                public Void run() {
                    //+ Java SecurityManager-Privileged
                    // This is expected to fail.
                    try {
                        System.out.println(System.getProperty("user.home"));
                    } catch (SecurityException e) {
                        e.printStackTrace(System.err);
                    }
                    AccessController.doPrivileged(new PrivilegedAction<Void>() {
                            public Void run() {
                                // This should work.
                                System.out.println(System.getProperty("user.home"));
                                return null;
                            }
                        });
                    //-
                    return null;
                }
            }, context);

    }

    //+ Java SecurityManager-Callback
    interface Callback<T> {
	T call(boolean flag);
    }

    class CallbackInvoker<T> {
	private final AccessControlContext context;
	Callback<T> callback;

	CallbackInvoker(Callback<T> callback) {
	    context = AccessController.getContext();
	    this.callback = callback;
	}

	public T invoke() {
	    // Obtain increased privileges.
	    return AccessController.doPrivileged(new PrivilegedAction<T>() {
		    @Override
		    public T run() {
			// This operation would fail without
			// additional privileges.
			final boolean flag = Boolean.getBoolean("some.property");

			// Restore the original privileges.
			return AccessController.doPrivileged(
                            new PrivilegedAction<T>() {
				@Override
				public T run() {
				    return callback.call(flag);
				}
			    }, context);
		    }
		});
	}
    }
    //-
}

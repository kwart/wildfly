package org.wildfly.test.manual.elytron.seccontext;

import java.net.URL;

import javax.ejb.Remote;

/**
 * Interface for the bean used as the entry point to verify EJB3 security behaviour.
 */
@Remote
public interface Entry {

    String readUrl(String username, String password, ReAuthnType type, final URL url, boolean manuallyRegisterAuthenticator);
}

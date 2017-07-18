package org.wildfly.test.manual.elytron.seccontext;

import java.net.URL;

import javax.ejb.Remote;

/**
 * Interface for the bean used as the entry point to verify EJB3 security behaviour.
 */
@Remote
public interface Entry {

    /**
     * @return The name of the Principal obtained from a call to EJBContext.getCallerPrincipal()
     */
    String whoAmI();

    /**
     * Obtains the name of the Principal obtained from a call to EJBContext.getCallerPrincipal() both for the bean called and
     * also from a call to a second bean (user may be switched before the second call - depending on arguments).
     *
     * @return An array containing the name from the local call first followed by the name from the second call.
     * @throws Exception - If there is an unexpected failure establishing the security context for the second call.
     */
    String[] doubleWhoAmI(String username, String password, ReAuthnType type, String providerUrl);

    String readUrl(String username, String password, ReAuthnType type, final URL url);
}

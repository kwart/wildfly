package org.wildfly.test.manual.elytron.seccontext;

import java.security.Principal;

import javax.ejb.Remote;

@Remote
public interface WhoAmI {

    /**
     * @return the caller principal obtained from the EJBContext.
     */
    Principal getCallerPrincipal();

}
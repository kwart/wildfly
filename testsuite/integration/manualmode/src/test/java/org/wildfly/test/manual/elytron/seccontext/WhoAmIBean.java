package org.wildfly.test.manual.elytron.seccontext;

import java.security.Principal;

import javax.annotation.Resource;
import javax.annotation.security.DeclareRoles;
import javax.annotation.security.RolesAllowed;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;

@Stateless
@RolesAllowed({ "whoami", "admin" })
@DeclareRoles({ "entry", "whoami", "servlet", "admin" })
public class WhoAmIBean implements WhoAmI {

    @Resource
    private SessionContext context;

    public Principal getCallerPrincipal() {
        return context.getCallerPrincipal();
    }

}

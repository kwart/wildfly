package org.wildfly.test.manual.elytron.seccontext;

import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.switchIdentity;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.Authenticator;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Callable;

import javax.annotation.Resource;
import javax.annotation.security.DeclareRoles;
import javax.annotation.security.RolesAllowed;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.wildfly.security.auth.util.ElytronAuthenticator;

@Stateless
@RolesAllowed({ "entry", "admin" })
@DeclareRoles({ "entry", "whoami", "servlet", "admin" })
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class EntryBean implements Entry {

    @Resource
    private SessionContext context;

    public String readUrl(String username, String password, ReAuthnType type, final URL url,
            boolean manuallyRegisterAuthenticator) {
        if (manuallyRegisterAuthenticator) {
            // workaround for JBEAP-12340
            Authenticator.setDefault(new ElytronAuthenticator());
        }
        final Callable<String> callable = () -> {
            URLConnection conn = url.openConnection();
            conn.connect();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                return br.readLine();
            }
        };
        String result = null;
        String firstWho = context.getCallerPrincipal().getName();
        try {
            result = switchIdentity(username, password, callable, type);
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            result = sw.toString();
        } finally {
            if (manuallyRegisterAuthenticator) {
                // workaround for JBEAP-12340
                Authenticator.setDefault(null);
            }
            String secondLocalWho = context.getCallerPrincipal().getName();
            if (!secondLocalWho.equals(firstWho)) {
                throw new IllegalStateException(
                        "Local getCallerPrincipal changed from '" + firstWho + "' to '" + secondLocalWho);
            }
        }
        return result;
    }

}

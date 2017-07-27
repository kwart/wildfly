package org.wildfly.test.manual.elytron.seccontext;

import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.SERVER2;
import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.switchIdentity;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
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
import javax.naming.NamingException;

@Stateless
@RolesAllowed({ "entry", "admin" })
@DeclareRoles({ "entry", "whoami", "servlet", "admin" })
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class EntryBean implements Entry {

    public static final String BEAN_REMOTE_NAME = SeccontextUtil.getRemoteEjbName(SERVER2, "WhoAmIBean",
            WhoAmI.class.getName());

    @Resource
    private SessionContext context;

    public String whoAmI() {
        return context.getCallerPrincipal().getName();
    }

    public String[] doubleWhoAmI(String username, String password, ReAuthnType type, final String providerUrl) {
        String[] result = new String[2];
        result[0] = context.getCallerPrincipal().getName();

        final Callable<String> callable = () -> {
            return getWhoAmIBean(providerUrl).getCallerPrincipal().getName();
        };
        try {
            result[1] = switchIdentity(username, password, callable, type);
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            result[1] = sw.toString();
        } finally {
            String secondLocalWho = context.getCallerPrincipal().getName();
            if (!secondLocalWho.equals(result[0])) {
                throw new IllegalStateException(
                        "Local getCallerPrincipal changed from '" + result[0] + "' to '" + secondLocalWho);
            }
        }
        return result;
    }

    public String readUrl(String username, String password, ReAuthnType type, final URL url) {
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
            String secondLocalWho = context.getCallerPrincipal().getName();
            if (!secondLocalWho.equals(firstWho)) {
                throw new IllegalStateException(
                        "Local getCallerPrincipal changed from '" + firstWho + "' to '" + secondLocalWho);
            }
        }
        return result;
    }

    private WhoAmI getWhoAmIBean(String providerUrl) throws NamingException {
        return SeccontextUtil.lookup(BEAN_REMOTE_NAME, providerUrl);
    }

}

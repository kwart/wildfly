/*
 * Copyright 2017 JBoss by Red Hat.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.test.integration.elytron.sasl.mgmt;

import static org.wildfly.test.integration.elytron.sasl.mgmt.AbstractMgmtSaslTestBase.PORT_NATIVE;
import static org.wildfly.test.integration.elytron.sasl.mgmt.AbstractMgmtSaslTestBase.assertWhoAmI;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.text.StrSubstitutor;
import org.apache.directory.api.ldap.model.constants.SupportedSaslMechanisms;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.annotations.SaslMechanism;
import org.apache.directory.server.core.annotations.AnnotationUtils;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.factory.DSAnnotationProcessor;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.factory.ServerAnnotationProcessor;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.sasl.cramMD5.CramMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.digestMD5.DigestMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.gssapi.GssapiMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.ntlm.NtlmMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.plain.PlainMechanismHandler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.network.NetworkUtils;
import org.jboss.as.test.integration.ldap.InMemoryDirectoryServiceFactory;
import org.jboss.as.test.integration.security.common.AbstractKrb5ConfServerSetupTask;
import org.jboss.as.test.integration.security.common.KDCServerAnnotationProcessor;
import org.jboss.as.test.integration.security.common.KerberosSystemPropertiesSetupTask;
import org.jboss.as.test.integration.security.common.Krb5LoginConfiguration;
import org.jboss.as.test.integration.security.common.ManagedCreateLdapServer;
import org.jboss.as.test.integration.security.common.SecurityTestConstants;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.logging.Logger;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.test.security.common.AbstractElytronSetupTask;
import org.wildfly.test.security.common.elytron.ConfigurableElement;
import org.wildfly.test.security.common.elytron.ConstantPermissionMapper;
import org.wildfly.test.security.common.elytron.CredentialReference;
import org.wildfly.test.security.common.elytron.DirContext;
import org.wildfly.test.security.common.elytron.IdentityMapping;
import org.wildfly.test.security.common.elytron.KerberosSecurityFactory;
import org.wildfly.test.security.common.elytron.LdapRealm;
import org.wildfly.test.security.common.elytron.MechanismConfiguration;
import org.wildfly.test.security.common.elytron.MechanismRealmConfiguration;
import org.wildfly.test.security.common.elytron.Path;
import org.wildfly.test.security.common.elytron.PermissionRef;
import org.wildfly.test.security.common.elytron.SaslFilter;
import org.wildfly.test.security.common.elytron.SimpleConfigurableSaslServerFactory;
import org.wildfly.test.security.common.elytron.SimpleSaslAuthenticationFactory;
import org.wildfly.test.security.common.elytron.SimpleSecurityDomain;
import org.wildfly.test.security.common.elytron.SimpleSecurityDomain.SecurityDomainRealm;
import org.wildfly.test.security.common.other.AccessIdentityConfigurator;
import org.wildfly.test.security.common.other.SimpleMgmtNativeInterface;
import org.wildfly.test.security.common.other.SimpleSocketBinding;

/**
 * Tests GSSAPI SASL mechanism used for management interface.
 *
 * @author Josef Cacek
 */
@RunWith(Arquillian.class)
@ServerSetup({ Gs2Krb5MgmtSaslTestCase.Krb5ConfServerSetupTask.class, //
        KerberosSystemPropertiesSetupTask.class, //
        Gs2Krb5MgmtSaslTestCase.DirectoryServerSetupTask.class, //
        // GssapiMgmtSaslTestCase.KeyMaterialSetup.class, //
        Gs2Krb5MgmtSaslTestCase.ServerSetup.class })
@RunAsClient
public class Gs2Krb5MgmtSaslTestCase {

    private static Logger LOGGER = Logger.getLogger(Gs2Krb5MgmtSaslTestCase.class);

    private static final String NAME = Gs2Krb5MgmtSaslTestCase.class.getSimpleName();
    private static final int LDAP_PORT = 10389;
    private static final String LDAP_URL = "ldap://"
            + NetworkUtils.formatPossibleIpv6Address(Utils.getSecondaryTestAddress(null, true)) + ":" + LDAP_PORT;

    private static final File WORK_DIR_GSSAPI;
    static {
        try {
            WORK_DIR_GSSAPI = Utils.createTemporaryFolder("gssapi-");
        } catch (IOException e) {
            throw new RuntimeException("Unable to create temporary folder", e);
        }
    }

    private static final File SERVER_KEYSTORE_FILE = new File(WORK_DIR_GSSAPI, SecurityTestConstants.SERVER_KEYSTORE);
    private static final File SERVER_TRUSTSTORE_FILE = new File(WORK_DIR_GSSAPI, SecurityTestConstants.SERVER_TRUSTSTORE);
    private static final File CLIENT_KEYSTORE_FILE = new File(WORK_DIR_GSSAPI, SecurityTestConstants.CLIENT_KEYSTORE);
    private static final File CLIENT_TRUSTSTORE_FILE = new File(WORK_DIR_GSSAPI, SecurityTestConstants.CLIENT_TRUSTSTORE);
    private static final File UNTRUSTED_STORE_FILE = new File(WORK_DIR_GSSAPI, SecurityTestConstants.UNTRUSTED_KEYSTORE);

    private static final String MECHANISM = "GS2-KRB5";

    // @Override
    protected String getMechanism() {
        return MECHANISM;
    }

    @Deployment(testable = false)
    public static WebArchive dummyDeployment() {
        return ShrinkWrap.create(WebArchive.class, NAME + ".war").addAsWebResource(new StringAsset("Test"), "index.html");
    }

    /**
     * Tests that client is able to use mechanism when server allows it.
     */
    @Test
    public void testCorrectMechanismPasses() throws Exception {
        final Krb5LoginConfiguration krb5Configuration = new Krb5LoginConfiguration(Utils.getLoginConfiguration());
        // Use our custom configuration to avoid reliance on external config
        Configuration.setConfiguration(krb5Configuration);
        try {
            // 1. Authenticate to Kerberos.
            final LoginContext lc = Utils.loginWithKerberos(krb5Configuration, "hnelson", "secret");
            try {
                AuthenticationConfiguration authCfg = AuthenticationConfiguration.empty()
                        .useProvidersFromClassLoader(Gs2Krb5MgmtSaslTestCase.class.getClassLoader())
                        .allowSaslMechanisms(MECHANISM).useGSSCredential(getGSSCredential(lc.getSubject()));

                AuthenticationContext.empty().with(MatchRule.ALL, authCfg).run(() -> assertWhoAmI("hnelson@JBOSS.ORG"));
            } finally {
                lc.logout();
            }
        } finally {
            krb5Configuration.resetConfiguration();
        }
    }

    @Test
    public void testAuthnFailsWithoutTicket() throws Exception {
        AuthenticationConfiguration authCfg = AuthenticationConfiguration.empty()
                .useProvidersFromClassLoader(Gs2Krb5MgmtSaslTestCase.class.getClassLoader()).allowSaslMechanisms(MECHANISM);

        AuthenticationContext.empty().with(MatchRule.ALL, authCfg).run(() -> AbstractMgmtSaslTestBase
                .assertAuthenticationFails("Authentication without Kerberos ticket should not be possible"));
    }

    private GSSCredential getGSSCredential(Subject subject) {
        return Subject.doAs(subject, new PrivilegedAction<GSSCredential>() {
            @Override
            public GSSCredential run() {
                try {
                    GSSManager gssManager = GSSManager.getInstance();
                    return gssManager.createCredential(GSSCredential.INITIATE_ONLY);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }
        });
    }

    /**
     * Setup task which configures Elytron security domains and remoting connectors for this test.
     */
    public static class ServerSetup extends AbstractElytronSetupTask {

        @Override
        protected ConfigurableElement[] getConfigurableElements() {
            List<ConfigurableElement> elements = new ArrayList<>();

            elements.add(ConstantPermissionMapper.builder().withName(NAME)
                    .withPermissions(PermissionRef.fromPermission(new LoginPermission())).build());

            // dir-context
            elements.add(DirContext.builder().withName(NAME).withUrl(LDAP_URL).withPrincipal("uid=admin,ou=system")
                    .withCredentialReference(CredentialReference.builder().withClearText("secret").build()).build());
            // ldap-realm
            elements.add(LdapRealm.builder()
                    .withName(NAME).withDirContext(NAME).withIdentityMapping(IdentityMapping.builder()
                            .withRdnIdentifier("krb5PrincipalName").withSearchBaseDn("ou=Users,dc=wildfly,dc=org").build())
                    .build());
            // security-domain
            elements.add(SimpleSecurityDomain.builder().withName(NAME).withDefaultRealm(NAME).withPermissionMapper(NAME)
                    .withRealms(SecurityDomainRealm.builder().withRealm(NAME).build()).build());
            elements.add(AccessIdentityConfigurator.builder().build());

            // kerberos-security-factory
            elements.add(
                    KerberosSecurityFactory
                            .builder().withName(NAME).withPrincipal(Krb5ConfServerSetupTask.REMOTE_PRINCIPAL).withPath(Path
                                    .builder().withPath(Krb5ConfServerSetupTask.REMOTE_KEYTAB_FILE.getAbsolutePath()).build())
                            .build());

            // SASL Authentication
            elements.add(SimpleConfigurableSaslServerFactory.builder().withName(NAME).withSaslServerFactory("elytron")
                    .addFilter(SaslFilter.builder().withPatternFilter(MECHANISM).build()).build());
            elements.add(
                    SimpleSaslAuthenticationFactory.builder().withName(NAME).withSaslServerFactory(NAME)
                            .withSecurityDomain(NAME)
                            .addMechanismConfiguration(MechanismConfiguration.builder().withMechanismName(MECHANISM)
                                    .addMechanismRealmConfiguration(
                                            MechanismRealmConfiguration.builder().withRealmName(NAME).build())
                                    .withCredentialSecurityFactory(NAME).build())
                            .build());

            // Socket binding and native management interface
            elements.add(SimpleSocketBinding.builder().withName(NAME).withPort(PORT_NATIVE).build());
            elements.add(
                    SimpleMgmtNativeInterface.builder().withSocketBinding(NAME).withSaslAuthenticationFactory(NAME).build());

            return elements.toArray(new ConfigurableElement[elements.size()]);
        }
    }

    public static class KeyMaterialSetup implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            FileUtils.deleteQuietly(WORK_DIR_GSSAPI);
            WORK_DIR_GSSAPI.mkdir();
            Utils.createKeyMaterial(WORK_DIR_GSSAPI);
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            FileUtils.deleteQuietly(WORK_DIR_GSSAPI);
        }

    }

    /**
     * Task which generates krb5.conf and keytab file(s).
     */
    public static class Krb5ConfServerSetupTask extends AbstractKrb5ConfServerSetupTask {
        public static final File HNELSON_KEYTAB_FILE = new File(WORK_DIR, "hnelson.keytab");
        public static final File JDUKE_KEYTAB_FILE = new File(WORK_DIR, "jduke.keytab");
        public static final String REMOTE_PRINCIPAL = "remote/" + Utils.getSecondaryTestAddress(null, true) + "@JBOSS.ORG";
        public static final File REMOTE_KEYTAB_FILE = new File(WORK_DIR, "remote.keytab");

        @Override
        protected List<UserForKeyTab> kerberosUsers() {
            List<UserForKeyTab> users = new ArrayList<UserForKeyTab>();
            users.add(new UserForKeyTab("hnelson@JBOSS.ORG", "secret", HNELSON_KEYTAB_FILE));
            users.add(new UserForKeyTab("jduke@JBOSS.ORG", "theduke", JDUKE_KEYTAB_FILE));
            users.add(new UserForKeyTab(REMOTE_PRINCIPAL, "zelvicka", REMOTE_KEYTAB_FILE));
            return users;
        }

    }

    //@formatter:off
    @CreateDS(
            name = "WildFlyDS",
            factory = InMemoryDirectoryServiceFactory.class,
            partitions = @CreatePartition(name = "wildfly", suffix = "dc=wildfly,dc=org"),
            additionalInterceptors = {KeyDerivationInterceptor.class},
            allowAnonAccess = true
        )
    @CreateKdcServer(primaryRealm = "JBOSS.ORG",
            kdcPrincipal = "krbtgt/JBOSS.ORG@JBOSS.ORG",
            searchBaseDn = "dc=wildfly,dc=org",
            transports =
                    {
                            @CreateTransport(protocol = "UDP", port = 6088)
                    })
    @CreateLdapServer(
            transports =
                    {
                            @CreateTransport(protocol = "LDAP", port = LDAP_PORT)
                    },
            saslHost = "localhost",
            saslPrincipal = "ldap/localhost@JBOSS.ORG",
            saslMechanisms =
                    {
                            @SaslMechanism(name = SupportedSaslMechanisms.PLAIN, implClass = PlainMechanismHandler.class),
                            @SaslMechanism(name = SupportedSaslMechanisms.CRAM_MD5, implClass = CramMd5MechanismHandler.class),
                            @SaslMechanism(name = SupportedSaslMechanisms.DIGEST_MD5, implClass = DigestMd5MechanismHandler.class),
                            @SaslMechanism(name = SupportedSaslMechanisms.GSSAPI, implClass = GssapiMechanismHandler.class),
                            @SaslMechanism(name = SupportedSaslMechanisms.NTLM, implClass = NtlmMechanismHandler.class),
                            @SaslMechanism(name = SupportedSaslMechanisms.GSS_SPNEGO, implClass = NtlmMechanismHandler.class)
                    })
    //@formatter:on
    static class DirectoryServerSetupTask implements ServerSetupTask {

        private DirectoryService directoryService;
        private KdcServer kdcServer;
        private LdapServer ldapServer;
        private boolean removeBouncyCastle = false;

        /**
         * Creates directory services, starts LDAP server and KDCServer
         *
         * @param managementClient
         * @param containerId
         * @throws Exception
         * @see org.jboss.as.arquillian.api.ServerSetupTask#setup(org.jboss.as.arquillian.container.ManagementClient,
         *      java.lang.String)
         */
        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            try {
                if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                    Security.addProvider(new BouncyCastleProvider());
                    removeBouncyCastle = true;
                }
            } catch (SecurityException ex) {
                LOGGER.warn("Cannot register BouncyCastleProvider", ex);
            }
            directoryService = DSAnnotationProcessor.getDirectoryService();
            final String hostname = Utils.getCannonicalHost(managementClient);
            final Map<String, String> map = new HashMap<String, String>();
            map.put("hostname", NetworkUtils.formatPossibleIpv6Address(hostname));
            final String secondaryTestAddress = NetworkUtils.canonize(Utils.getSecondaryTestAddress(managementClient, true));
            map.put("ldaphost", secondaryTestAddress);
            final String ldifContent = StrSubstitutor.replace(
                    IOUtils.toString(Gs2Krb5MgmtSaslTestCase.class.getResourceAsStream("remoting-krb5-test.ldif"), "UTF-8"),
                    map);
            LOGGER.trace(ldifContent);
            final SchemaManager schemaManager = directoryService.getSchemaManager();
            try {
                for (LdifEntry ldifEntry : new LdifReader(IOUtils.toInputStream(ldifContent, StandardCharsets.UTF_8))) {
                    directoryService.getAdminSession().add(new DefaultEntry(schemaManager, ldifEntry.getEntry()));
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw e;
            }
            kdcServer = KDCServerAnnotationProcessor.getKdcServer(directoryService, 1024, hostname);
            final ManagedCreateLdapServer createLdapServer = new ManagedCreateLdapServer(
                    (CreateLdapServer) AnnotationUtils.getInstance(CreateLdapServer.class));
            createLdapServer.setSaslHost(secondaryTestAddress);
            createLdapServer.setSaslPrincipal("ldap/" + secondaryTestAddress + "@JBOSS.ORG");
            Utils.fixApacheDSTransportAddress(createLdapServer, secondaryTestAddress);
            ldapServer = ServerAnnotationProcessor.instantiateLdapServer(createLdapServer, directoryService);
            ldapServer.getSaslHost();
            ldapServer.setSearchBaseDn("dc=wildfly,dc=org");
            ldapServer.start();
        }

        /**
         * Stops LDAP server and KDCServer and shuts down the directory service.
         *
         * @param managementClient
         * @param containerId
         * @throws Exception
         * @see org.jboss.as.arquillian.api.ServerSetupTask#tearDown(org.jboss.as.arquillian.container.ManagementClient,
         *      java.lang.String)
         */
        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            ldapServer.stop();
            kdcServer.stop();
            directoryService.shutdown();
            FileUtils.deleteDirectory(directoryService.getInstanceLayout().getInstanceDirectory());
            if (removeBouncyCastle) {
                try {
                    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
                } catch (SecurityException ex) {
                    LOGGER.warn("Cannot deregister BouncyCastleProvider", ex);
                }
            }

        }
    }

}

/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.test.integration.elytron.sasl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.List;
import java.util.Properties;

import javax.jms.ConnectionFactory;
import javax.jms.Destination;
import javax.jms.JMSConsumer;
import javax.jms.JMSContext;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.security.sasl.SaslException;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.io.FileUtils;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.AnnotationUtils;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.factory.DSAnnotationProcessor;
import org.apache.directory.server.factory.ServerAnnotationProcessor;
import org.apache.directory.server.ldap.LdapServer;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.network.NetworkUtils;
import org.jboss.as.test.integration.common.jms.ActiveMQProviderJMSOperations;
import org.jboss.as.test.integration.ldap.InMemoryDirectoryServiceFactory;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.jboss.as.test.integration.security.common.ManagedCreateLdapServer;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.logging.Logger;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.naming.client.WildFlyInitialContextFactory;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.test.security.common.AbstractElytronSetupTask;
import org.wildfly.test.security.common.elytron.ConfigurableElement;
import org.wildfly.test.security.common.elytron.ConstantPermissionMapper;
import org.wildfly.test.security.common.elytron.ConstantRoleMapper;
import org.wildfly.test.security.common.elytron.MechanismConfiguration;
import org.wildfly.test.security.common.elytron.PermissionRef;
import org.wildfly.test.security.common.elytron.SaslFilter;
import org.wildfly.test.security.common.elytron.SimpleConfigurableSaslServerFactory;
import org.wildfly.test.security.common.elytron.SimpleSaslAuthenticationFactory;
import org.wildfly.test.security.common.elytron.SimpleSecurityDomain;
import org.wildfly.test.security.common.elytron.SimpleSecurityDomain.SecurityDomainRealm;
import org.wildfly.test.security.common.other.SimpleRemotingConnector;
import org.wildfly.test.security.common.other.SimpleSocketBinding;

/**
 *
 * @author Josef Cacek
 */
@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup({ SaslJmsClientTestCase.JmsAndLdapSetup.class, SaslJmsClientTestCase.ServerSetup.class })
public class SaslJmsClientTestCase {

    private static Logger LOGGER = Logger.getLogger(SaslJmsClientTestCase.class);

    private static final String NAME = SaslJmsClientTestCase.class.getSimpleName();
    private static final String JNDI_QUEUE_NAME = "java:jboss/exported/" + NAME;

    private static final String ANONYMOUS = "ANONYMOUS";
    private static final int PORT_ANONYMOUS = 10567;

    private static final String DEFAULT_SASL_AUTHENTICATION = "application-sasl-authentication";
    private static final String DEFAULT = "DEFAULT";
    private static final int PORT_DEFAULT = 10568;

    private static final String OTP = "OTP";
    private static final String OTP_ALGORITHM = "otp-sha1";
    private static final String OTP_PASSPHRASE = "This is a test.";
    private static final String OTP_SEED = "TeSt";
    // https://www.ocf.berkeley.edu/~jjlin/jsotp/
    // http://tomeko.net/online_tools/hex_to_base64.php?lang=en
    private static final byte[] OTP_HASH_99 = DatatypeConverter.parseHexBinary("87FEC7768B73CCF9");
    private static final byte[] OTP_HASH_98 = DatatypeConverter.parseHexBinary("33D865A2BF9E5E76");
    private static final int PORT_OTP = 10569;

    private static final String MESSAGE = "Hello, World!";
    private static final String CONNECTION_FACTORY = "jms/RemoteConnectionFactory";

    private static final int LDAP_PORT = 10389;

    private static final String HOST = Utils.getDefaultHost(false);
    private static final String HOST_FMT = NetworkUtils.formatPossibleIpv6Address(HOST);
    private static final String LDAP_URL = "ldap://" + HOST_FMT + ":" + LDAP_PORT;

    @Deployment(testable = false)
    public static WebArchive dummyDeployment() {
        return ShrinkWrap.create(WebArchive.class, NAME + ".war").addAsWebResource(new StringAsset("Test"), "index.html");
    }

    @Test
    public void testAnonymousFailsInDefault() throws Exception {
        // Anonymous not supported in the default configuration
        AuthenticationContext.empty()
                .with(MatchRule.ALL,
                        AuthenticationConfiguration.EMPTY.useDefaultProviders().allowSaslMechanisms(ANONYMOUS)
                                .useAuthorizationPrincipal(AnonymousPrincipal.getInstance()))
                .run(() -> sendAndReceiveMsg(PORT_DEFAULT, true));
    }

    @Test
    public void testJBossLocalInDefault() throws Exception {
        AuthenticationContext.empty()
                .with(MatchRule.ALL,
                        AuthenticationConfiguration.EMPTY.useDefaultProviders().allowSaslMechanisms("JBOSS-LOCAL-USER"))
                .run(() -> sendAndReceiveMsg(PORT_DEFAULT, false));
    }

    @Test
    public void testDigestInDefault() throws Exception {
        AuthenticationContext
                .empty().with(MatchRule.ALL, AuthenticationConfiguration.EMPTY.useDefaultProviders()
                        .allowSaslMechanisms("DIGEST-MD5").useName("guest").usePassword("guest"))
                .run(() -> sendAndReceiveMsg(PORT_DEFAULT, false));
    }

    @Test
    public void testAnonymousAccess() throws Exception {
        AuthenticationContext.empty()
                .with(MatchRule.ALL,
                        AuthenticationConfiguration.EMPTY.useDefaultProviders().allowSaslMechanisms(ANONYMOUS)
                                .useAuthorizationPrincipal(AnonymousPrincipal.getInstance()))
                .run(() -> sendAndReceiveMsg(PORT_ANONYMOUS, false));
    }

    @Test
    public void testOtpAccess() throws Exception {
        assertSequenceAndHash(99, OTP_HASH_99);
        Runnable runAndExpectFail = () -> sendAndReceiveMsg(PORT_OTP, true);
        AuthenticationContext.empty()
                .with(MatchRule.ALL, AuthenticationConfiguration.EMPTY.useDefaultProviders().allowSaslMechanisms(OTP))
                .run(runAndExpectFail);
        assertSequenceAndHash(99, OTP_HASH_99);
        AuthenticationContext.empty().with(MatchRule.ALL, AuthenticationConfiguration.EMPTY.useDefaultProviders()
                .allowSaslMechanisms(OTP).useName("jduke").usePassword("TeSt")).run(runAndExpectFail);
        assertSequenceAndHash(99, OTP_HASH_99);
        AuthenticationContext.empty().with(MatchRule.ALL, AuthenticationConfiguration.EMPTY.useDefaultProviders()
                .allowSaslMechanisms(OTP).useName("jduke").usePassword(OTP_PASSPHRASE))
                .run(() -> sendAndReceiveMsg(PORT_OTP, false));
        assertSequenceAndHash(98, OTP_HASH_98);
    }

    private void assertSequenceAndHash(Integer expectedSequence, byte[] expectedHash) throws NamingException {
        final Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, LDAP_URL);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.put(Context.SECURITY_CREDENTIALS, "secret");
        final LdapContext ctx = new InitialLdapContext(env, null);
        NamingEnumeration<?> namingEnum = ctx.search("dc=wildfly,dc=org", new BasicAttributes("cn", "jduke"));
        if (namingEnum.hasMore()) {
            SearchResult sr = (SearchResult) namingEnum.next();
            Attributes attrs = sr.getAttributes();
            assertEquals("Unexpected sequence number in LDAP attribute", expectedSequence,
                    new Integer(attrs.get("telephoneNumber").get().toString()));
            assertEquals("Unexpected hash value in LDAP attribute", Base64.getEncoder().encodeToString(expectedHash),
                    attrs.get("title").get().toString());
        } else {
            fail("User not found in LDAP");
        }

        namingEnum.close();
        ctx.close();
    }

    private void sendAndReceiveMsg(int remotingPort, boolean expectedSaslFail) {
        Context namingContext = null;

        try {
            // Set up the namingContext for the JNDI lookup
            final Properties env = new Properties();
            env.put(Context.INITIAL_CONTEXT_FACTORY, WildFlyInitialContextFactory.class.getName());
            env.put("remote.connectionprovider.create.options.org.xnio.Options.SSL_ENABLED", "false");
            env.put(Context.PROVIDER_URL, "remote://" + HOST_FMT + ":" + remotingPort);
            namingContext = new InitialContext(env);

            // Perform the JNDI lookups
            ConnectionFactory connectionFactory = null;
            try {
                connectionFactory = (ConnectionFactory) namingContext.lookup(CONNECTION_FACTORY);
                assertFalse("JNDI lookup should have failed.", expectedSaslFail);
            } catch (NamingException e) {
                assertTrue("Unexpected JNDI lookup failure.", expectedSaslFail);
                // only SASL failures are expected
                assertTrue("Unexpected cause of lookup failure", e.getCause() instanceof SaslException);
                return;
            }

            Destination destination = (Destination) namingContext.lookup(NAME);

            int count = 1;

            try (JMSContext context = connectionFactory.createContext()) {
                // Send the specified number of messages
                for (int i = 0; i < count; i++) {
                    context.createProducer().send(destination, MESSAGE);
                }

                // Create the JMS consumer
                JMSConsumer consumer = context.createConsumer(destination);
                // Then receive the same number of messages that were sent
                for (int i = 0; i < count; i++) {
                    String text = consumer.receiveBody(String.class, 5000);
                    Assert.assertEquals(MESSAGE, text);
                }
            }
        } catch (NamingException e) {
            LOGGER.error("Naming problem occured.", e);
            throw new RuntimeException(e);
        } finally {
            if (namingContext != null) {
                try {
                    namingContext.close();
                } catch (NamingException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static class JmsAndLdapSetup implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            new ActiveMQProviderJMSOperations(managementClient).createJmsQueue(NAME, JNDI_QUEUE_NAME);
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            new ActiveMQProviderJMSOperations(managementClient).removeJmsQueue(NAME);
        }

    }

    /**
     * Setup task which configures Elytron security domains for this test.
     */
    public static class ServerSetup extends AbstractElytronSetupTask {

        @Override
        protected ConfigurableElement[] getConfigurableElements() {
            List<ConfigurableElement> elements = new ArrayList<>();

            elements.add(ConstantPermissionMapper.builder().withName(NAME)
                    .withPermissions(PermissionRef.fromPermission(new LoginPermission())).build());
            elements.add(ConstantRoleMapper.builder().withName(NAME).withRoles("guest").build());
            elements.add(SimpleSecurityDomain.builder().withName(NAME).withDefaultRealm("ApplicationRealm").withRoleMapper(NAME)
                    .withPermissionMapper(NAME).withRealms(SecurityDomainRealm.builder().withRealm("ApplicationRealm").build())
                    .build());

            elements.add(new OtpLdapConf());
            elements.add(SimpleSecurityDomain.builder().withName(OTP).withDefaultRealm(OTP).withPermissionMapper(NAME)
                    .withRealms(SecurityDomainRealm.builder().withRealm(OTP).withRoleDecoder("groups-to-roles").build())
                    .build());

            elements.add(SimpleConfigurableSaslServerFactory.builder().withName(OTP).withSaslServerFactory("elytron")
                    .addFilter(SaslFilter.builder().withPatternFilter(OTP).build()).build());
            elements.add(SimpleSaslAuthenticationFactory.builder().withName(OTP).withSaslServerFactory(OTP)
                    .withSecurityDomain(OTP)
                    .addMechanismConfiguration(MechanismConfiguration.builder().withMechanismName(OTP).build()).build());

            elements.add(SimpleSocketBinding.builder().withName(OTP).withPort(PORT_OTP).build());
            elements.add(SimpleRemotingConnector.builder().withName(OTP).withSocketBinding(OTP)
                    .withSaslAuthenticationFactory(OTP).build());

            elements.add(SimpleConfigurableSaslServerFactory.builder().withName(ANONYMOUS).withSaslServerFactory("elytron")
                    .addFilter(SaslFilter.builder().withPatternFilter(ANONYMOUS).build()).build());
            elements.add(SimpleSaslAuthenticationFactory.builder().withName(ANONYMOUS).withSaslServerFactory(ANONYMOUS)
                    .withSecurityDomain(NAME)
                    .addMechanismConfiguration(MechanismConfiguration.builder().withMechanismName(ANONYMOUS).build()).build());

            elements.add(SimpleSocketBinding.builder().withName(ANONYMOUS).withPort(PORT_ANONYMOUS).build());
            elements.add(SimpleRemotingConnector.builder().withName(ANONYMOUS).withSocketBinding(ANONYMOUS)
                    .withSaslAuthenticationFactory(ANONYMOUS).build());

            elements.add(SimpleSocketBinding.builder().withName(DEFAULT).withPort(PORT_DEFAULT).build());
            elements.add(SimpleRemotingConnector.builder().withName(DEFAULT).withSocketBinding(DEFAULT)
                    .withSaslAuthenticationFactory(DEFAULT_SASL_AUTHENTICATION).build());

            return elements.toArray(new ConfigurableElement[elements.size()]);
        }

        //@formatter:off
        @CreateDS(
                name = "WildFlyDS",
                factory = InMemoryDirectoryServiceFactory.class,
                partitions = @CreatePartition(name = "wildfly", suffix = "dc=wildfly,dc=org"),
                allowAnonAccess = true
            )
            @CreateLdapServer(
                transports = @CreateTransport(protocol = "LDAP", address = "localhost", port = LDAP_PORT),
                allowAnonymousAccess = true
            )
        //@formatter:on
        private static class OtpLdapConf implements ConfigurableElement {

            private static DirectoryService directoryService;
            private static LdapServer ldapServer;

            @Override
            public void create(CLIWrapper cli) throws Exception {
                Encoder b64e = Base64.getEncoder();
                directoryService = DSAnnotationProcessor.getDirectoryService();
                DSAnnotationProcessor.injectEntries(directoryService,
                        "dn: dc=wildfly,dc=org\n" //
                                + "dc: jboss\n" //
                                + "objectClass: top\n" //
                                + "objectClass: domain\n" //
                                + "\n" //
                                + "dn: cn=jduke,dc=wildfly,dc=org\n" //
                                + "objectclass: top\n" //
                                + "objectclass: person\n" //
                                + "objectclass: organizationalPerson\n" //
                                + "cn: jduke\n" //
                                + "street: guest\n" // role ;)
                                + "sn: " + OTP_ALGORITHM + "\n" // algorithm
                                + "title: " + b64e.encodeToString(OTP_HASH_99) + "\n" // stored hash
                                + "description: " + b64e.encodeToString(OTP_SEED.getBytes(StandardCharsets.US_ASCII)) + "\n" // seed
                                + "telephoneNumber: 99\n" // sequence
                );
                final ManagedCreateLdapServer createLdapServer = new ManagedCreateLdapServer(
                        (CreateLdapServer) AnnotationUtils.getInstance(CreateLdapServer.class));
                Utils.fixApacheDSTransportAddress(createLdapServer, Utils.getSecondaryTestAddress(null, false));
                ldapServer = ServerAnnotationProcessor.instantiateLdapServer(createLdapServer, directoryService);
                ldapServer.start();

                cli.sendLine(String.format(
                        "/subsystem=elytron/dir-context=%s:add(url=\"%s\",principal=\"uid=admin,ou=system\",credential-reference={clear-text=secret})",
                        OTP, LDAP_URL));
                cli.sendLine(String
                        .format("/subsystem=elytron/ldap-realm=%s:add(dir-context=%s,identity-mapping={rdn-identifier=cn,search-base-dn=\"dc=wildfly,dc=org\","
                                + "otp-credential-mapper={algorithm-from=sn, hash-from=title, seed-from=description, sequence-from=telephoneNumber},"
                                + "attribute-mapping=[{from=street,to=groups}]})", OTP, OTP));
                // cli.sendLine(String.format(
                // "/subsystem=elytron/ldap-realm=%s:add(dir-context=%s,identity-mapping={rdn-identifier=cn,search-base-dn=\"dc=wildfly,dc=org\",user-password-mapper={from=userPassword},attribute-mapping=[{filter-base-dn=\"ou=Roles,dc=jboss,dc=org\",filter=\"(member={1})\",from=cn,to=groups}]})",
                // OTP, OTP));
                // cli.sendLine(String.format(
                // "/subsystem=elytron/security-domain=%1$s:add(realms=[{realm=%2$s,role-decoder=groups-to-roles}],default-realm=%2$s,permission-mapper=default-permission-mapper)",
                // OTP, OTP));
            }

            @Override
            public void remove(CLIWrapper cli) throws Exception {
                // cli.sendLine(String.format("/subsystem=elytron/security-domain=%s:remove()", OTP));
                cli.sendLine(String.format("/subsystem=elytron/ldap-realm=%s:remove()", OTP));
                cli.sendLine(String.format("/subsystem=elytron/dir-context=%s:remove()", OTP));

                ldapServer.stop();
                directoryService.shutdown();
                FileUtils.deleteDirectory(directoryService.getInstanceLayout().getInstanceDirectory());
            }

            @Override
            public String getName() {
                return "ldap-configuration";
            }
        }

    }
}

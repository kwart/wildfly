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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.ConnectException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;

import javax.security.sasl.SaslException;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.client.ModelControllerClientConfiguration;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.test.security.common.AbstractElytronSetupTask;
import org.wildfly.test.security.common.elytron.ConfigurableElement;
import org.wildfly.test.security.common.elytron.ConstantPermissionMapper;
import org.wildfly.test.security.common.elytron.FileSystemRealm;
import org.wildfly.test.security.common.elytron.MechanismConfiguration;
import org.wildfly.test.security.common.elytron.PermissionRef;
import org.wildfly.test.security.common.elytron.SaslFilter;
import org.wildfly.test.security.common.elytron.SimpleConfigurableSaslServerFactory;
import org.wildfly.test.security.common.elytron.SimpleSaslAuthenticationFactory;
import org.wildfly.test.security.common.elytron.SimpleSecurityDomain;
import org.wildfly.test.security.common.elytron.SimpleSecurityDomain.SecurityDomainRealm;
import org.wildfly.test.security.common.other.SimpleMgmtNativeInterface;
import org.wildfly.test.security.common.other.SimpleSocketBinding;

/**
 * Tests PLAIN SASL mechanism used for management interface.
 *
 * @author Josef Cacek
 */
@RunWith(Arquillian.class)
@ServerSetup({ ReproducerPlainClientClassTestCase.ServerSetup.class })
@RunAsClient
public class ReproducerPlainClientClassTestCase {

    private static final String MECHANISM_PLAIN = "PLAIN";
    protected static final String USERNAME = "guest";
    protected static final int PORT_NATIVE = 10567;
    protected static final int CONNECTION_TIMEOUT_IN_MS = 600 * 1000;
    protected static final String NAME = ReproducerPlainClientClassTestCase.class.getSimpleName();

    @Deployment(testable = false)
    public static WebArchive dummyDeployment() {
        return ShrinkWrap.create(WebArchive.class, NAME + ".war").addAsWebResource(new StringAsset("Test"), "index.html");
    }

    /**
     * Tests that invalid credentials results in authentication failure.
     */
    @Test
    public void testWrongCredentialsFailDefaultProviders() throws Exception {
        AuthenticationConfiguration authnCfg = AuthenticationConfiguration.empty().allowSaslMechanisms(MECHANISM_PLAIN)
                .useName(USERNAME).usePassword("wrongPassword")
                .useDefaultProviders()
                ;

        AuthenticationContext.empty().with(MatchRule.ALL, authnCfg).run((Runnable) () -> {
            final long startTime = System.currentTimeMillis();
            try {
                ModelControllerClient client = ModelControllerClient.Factory
                        .create(new ModelControllerClientConfiguration.Builder().setHostName(Utils.getDefaultHost(false))
                                .setPort(PORT_NATIVE).setProtocol("remote").setConnectionTimeout(CONNECTION_TIMEOUT_IN_MS)
                                .build());

                ModelNode operation = new ModelNode();
                operation.get("operation").set("whoami");
                operation.get("verbose").set("true");

                client.execute(operation);

                fail("Operation failure was expected");
            } catch (IOException e) {
                assertTrue("Connection reached its timeout (hang).",
                        startTime + CONNECTION_TIMEOUT_IN_MS > System.currentTimeMillis());
                Throwable cause = e.getCause();
                assertThat("ConnectionException was expected as a cause when SASL authentication fails", cause,
                        is(instanceOf(ConnectException.class)));
                assertThat("SaslException was expected as the second cause when SASL authentication fails", cause.getCause(),
                        is(instanceOf(SaslException.class)));
            }
        });
    }

    /**
     * Tests that invalid credentials results in authentication failure.
     */
    @Test
    public void testWrongCredentialsFailElytronOnly() throws Exception {
        AuthenticationConfiguration authnCfg = AuthenticationConfiguration.empty().allowSaslMechanisms(MECHANISM_PLAIN)
                .useName(USERNAME).usePassword("wrongPassword")
                .useProviders(() -> new Provider[] { new WildFlyElytronProvider() })
                ;

        AuthenticationContext.empty().with(MatchRule.ALL, authnCfg).run((Runnable) () -> {
            final long startTime = System.currentTimeMillis();
            try {
                ModelControllerClient client = ModelControllerClient.Factory
                        .create(new ModelControllerClientConfiguration.Builder().setHostName(Utils.getDefaultHost(false))
                                .setPort(PORT_NATIVE).setProtocol("remote").setConnectionTimeout(CONNECTION_TIMEOUT_IN_MS)
                                .build());

                ModelNode operation = new ModelNode();
                operation.get("operation").set("whoami");
                operation.get("verbose").set("true");

                client.execute(operation);

                fail("Operation failure was expected");
            } catch (IOException e) {
                assertTrue("Connection reached its timeout (hang).",
                        startTime + CONNECTION_TIMEOUT_IN_MS > System.currentTimeMillis());
                Throwable cause = e.getCause();
                assertThat("ConnectionException was expected as a cause when SASL authentication fails", cause,
                        is(instanceOf(ConnectException.class)));
                assertThat("SaslException was expected as the second cause when SASL authentication fails", cause.getCause(),
                        is(instanceOf(SaslException.class)));
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
            elements.add(FileSystemRealm.builder().withName(NAME).withUser(USERNAME, USERNAME).build());
            elements.add(SimpleSecurityDomain.builder().withName(NAME).withDefaultRealm("ApplicationRealm")
                    .withPermissionMapper(NAME).withRealms(SecurityDomainRealm.builder().withRealm("ApplicationRealm").build())
                    .build());

            elements.add(new ConfigurableElement() {

                @Override
                public void create(CLIWrapper cli) throws Exception {
                    cli.sendLine(String.format(
                            "/subsystem=elytron/security-domain=ManagementDomain:write-attribute(name=trusted-security-domains, value=[%s])",
                            NAME));
                }

                @Override
                public void remove(CLIWrapper cli) throws Exception {
                    cli.sendLine(
                            "/subsystem=elytron/security-domain=ManagementDomain:undefine-attribute(name=trusted-security-domains)");
                }

                @Override
                public String getName() {
                    return "domain-trust";
                }
            });

            elements.add(SimpleConfigurableSaslServerFactory.builder().withName(NAME).withSaslServerFactory("elytron")
                    .addFilter(SaslFilter.builder().withPatternFilter(MECHANISM_PLAIN).build()).build());
            elements.add(SimpleSaslAuthenticationFactory.builder().withName(NAME).withSaslServerFactory(NAME)
                    .withSecurityDomain(NAME)
                    .addMechanismConfiguration(MechanismConfiguration.builder().withMechanismName(MECHANISM_PLAIN).build())
                    .build());

            elements.add(SimpleSocketBinding.builder().withName(NAME).withPort(PORT_NATIVE).build());
            elements.add(
                    SimpleMgmtNativeInterface.builder().withSocketBinding(NAME).withSaslAuthenticationFactory(NAME).build());

            return elements.toArray(new ConfigurableElement[elements.size()]);
        }
    }
}

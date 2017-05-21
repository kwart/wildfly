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

import java.io.IOException;
import java.net.ConnectException;
import java.util.ArrayList;
import java.util.List;

import javax.security.sasl.SaslException;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.client.ModelControllerClientConfiguration;
import org.jboss.as.controller.client.helpers.Operations;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.test.security.common.AbstractElytronSetupTask;
import org.wildfly.test.security.common.elytron.ConfigurableElement;
import org.wildfly.test.security.common.elytron.ConstantPermissionMapper;
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
 * Tests default SASL configuration for management interface.
 *
 * @author Josef Cacek
 */
@RunWith(Arquillian.class)
@ServerSetup(MgmtAnonymousSaslTestCase.ServerSetup.class)
public class MgmtAnonymousSaslTestCase {

    private static final String NAME = MgmtAnonymousSaslTestCase.class.getSimpleName();
    private static final String ANONYMOUS = "ANONYMOUS";
    private static final int PORT_ANONYMOUS = 10567;


    @Deployment(testable = false)
    public static WebArchive dummyDeployment() {
        return ShrinkWrap.create(WebArchive.class, NAME + ".war").addAsWebResource(new StringAsset("Test"), "index.html");
    }

    /**
     * Tests that client is able to use ANONYMOUS SASL mechanism when server allows it.
     */
    @Test
    public void testAnonymousAccess() throws Exception {
        AuthenticationContext.empty()
                .with(MatchRule.ALL,
                        AuthenticationConfiguration.EMPTY.useDefaultProviders().allowSaslMechanisms(ANONYMOUS)
                        .setSaslMechanismSelector(SaslMechanismSelector.fromString(ANONYMOUS))
                        .useAnonymous())
                .run(() -> assertWhoAmI("anonymous"));
    }

    private void assertAuthenticationFails() {
        try {
            executeWhoAmI();
        } catch (IOException e) {
            Throwable cause = e.getCause();
            Assert.assertThat(cause, is(instanceOf(ConnectException.class)));
            Assert.assertThat(cause.getCause(), is(instanceOf(SaslException.class)));
        }
    }

    private ModelNode executeWhoAmI() throws IOException {
        ModelControllerClient client = ModelControllerClient.Factory.create(new ModelControllerClientConfiguration.Builder()
                .setHostName(Utils.getDefaultHost(false)).setPort(PORT_ANONYMOUS)
                .setProtocol("remote")
                .setConnectionTimeout(2000).build());

        ModelNode operation = new ModelNode();
        operation.get("operation").set("whoami");
        operation.get("verbose").set("true");

        return client.execute(operation);
    }

    private void assertWhoAmI(String expected) {
        try {
            ModelNode result = executeWhoAmI();
            Assert.assertTrue("The whoami operation should finish with success", Operations.isSuccessfulOutcome(result));
            Assert.assertEquals("The whoami operation returned unexpected value", expected,
                    Operations.readResult(result).get("identity").get("username").asString());
        } catch (IOException e) {
            Assert.fail("The whoami operation failed - " + e.getMessage());
        }
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
            // elements.add(ConstantRoleMapper.builder().withName(NAME).withRoles("guest").build());
            elements.add(SimpleSecurityDomain.builder().withName(NAME).withDefaultRealm("ApplicationRealm")
                    .withPermissionMapper(NAME).withRealms(SecurityDomainRealm.builder().withRealm("ApplicationRealm").build())
                    .build());

            elements.add(SimpleConfigurableSaslServerFactory.builder().withName(NAME).withSaslServerFactory("elytron")
                    .addFilter(SaslFilter.builder().withPatternFilter(ANONYMOUS).build()).build());
            elements.add(SimpleSaslAuthenticationFactory.builder().withName(NAME).withSaslServerFactory(NAME)
                    .withSecurityDomain(NAME)
                    .addMechanismConfiguration(MechanismConfiguration.builder().withMechanismName(ANONYMOUS).build()).build());

            elements.add(SimpleSocketBinding.builder().withName(NAME).withPort(PORT_ANONYMOUS).build());
            elements.add(
                    SimpleMgmtNativeInterface.builder().withSocketBinding(NAME).withSaslAuthenticationFactory(NAME).build());

            return elements.toArray(new ConfigurableElement[elements.size()]);
        }
    }

}

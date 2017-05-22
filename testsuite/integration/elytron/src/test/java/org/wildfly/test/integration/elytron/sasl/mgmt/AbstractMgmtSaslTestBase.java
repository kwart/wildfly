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
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.client.ModelControllerClientConfiguration;
import org.jboss.as.controller.client.helpers.Operations;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.dmr.ModelNode;
import org.jboss.logging.Logger;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.permission.LoginPermission;
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
import org.wildfly.test.security.common.other.SimpleMgmtNativeInterface;
import org.wildfly.test.security.common.other.SimpleSocketBinding;

/**
 * Tests default SASL configuration for management interface.
 *
 * @author Josef Cacek
 */
public abstract class AbstractMgmtSaslTestBase {

    private static Logger LOGGER = Logger.getLogger(AbstractMgmtSaslTestBase.class);

    protected static final String NAME = AbstractMgmtSaslTestBase.class.getSimpleName();
    protected static final int PORT_NATIVE = 10567;
    protected static final String APPLICATION_FS_REALM = "ApplicationFsRealm";
    protected static final String ROLE_SASL = "sasl";

    protected static final String USERNAME = "guest";
    protected static final String PASSWORD = "guest";

    @Deployment(testable = false)
    public static WebArchive dummyDeployment() {
        return ShrinkWrap.create(WebArchive.class, NAME + ".war").addAsWebResource(new StringAsset("Test"), "index.html");
    }

    protected void assertAuthenticationFails() {
        try {
            executeWhoAmI();
        } catch (IOException e) {
            Throwable cause = e.getCause();
            Assert.assertThat(cause, is(instanceOf(ConnectException.class)));
            Assert.assertThat(cause.getCause(), is(instanceOf(SaslException.class)));
        }
    }

    protected ModelNode executeWhoAmI() throws IOException {
        ModelControllerClient client = ModelControllerClient.Factory
                .create(new ModelControllerClientConfiguration.Builder().setHostName(Utils.getDefaultHost(false))
                        .setPort(PORT_NATIVE).setProtocol("remote").setConnectionTimeout(2000).build());

        ModelNode operation = new ModelNode();
        operation.get("operation").set("whoami");
        operation.get("verbose").set("true");

        return client.execute(operation);
    }

    protected void assertWhoAmI(String expected) {
        try {
            ModelNode result = executeWhoAmI();
            Assert.assertTrue("The whoami operation should finish with success", Operations.isSuccessfulOutcome(result));
            Assert.assertEquals("The whoami operation returned unexpected value", expected,
                    Operations.readResult(result).get("identity").get("username").asString());
        } catch (IOException e) {
            LOGGER.warn("Operation execution failed", e);
            Assert.fail("The whoami operation failed - " + e.getMessage());
        }
    }

    protected AuthenticationContext createValidConfigForMechanism(String mechanismName) {
        AuthenticationConfiguration authnCfg = AuthenticationConfiguration.EMPTY.allowSaslMechanisms(mechanismName)
        // FIXME commented out due to WFLY-8742
        // .useDefaultProviders()
        ;
        if ("ANONYMOUS".equals(mechanismName)) {
            authnCfg = authnCfg.useAnonymous();
        } else if (!"JBOSS-LOCAL-USER".equals(mechanismName)) {
            authnCfg = authnCfg.useName(USERNAME).usePassword(PASSWORD);
        }
        return AuthenticationContext.empty().with(MatchRule.ALL, authnCfg);
    }

    protected void assertMechFails(String mechanismName) {
        createValidConfigForMechanism(mechanismName).run(() -> assertAuthenticationFails());
    }

    protected void assertMechPassWhoAmI(String mechanismName, String expectedUsername) {
        createValidConfigForMechanism(mechanismName).run(() -> assertWhoAmI(expectedUsername));
    }

    /**
     * Creates a new list or ConfigurableElements with basic SASL settings for native management interface.
     *
     * @param saslMechanismName Name of single SASL mechanism to be allowed on server.
     * @return new list (modifiable)
     */
    protected static List<ConfigurableElement> createConfigurableElementsForSaslMech(String saslMechanismName) {
        List<ConfigurableElement> elements = new ArrayList<>();

        elements.add(ConstantPermissionMapper.builder().withName(NAME)
                .withPermissions(PermissionRef.fromPermission(new LoginPermission())).build());
        elements.add(ConstantRoleMapper.builder().withName(NAME).withRoles(ROLE_SASL).build());
        elements.add(SimpleSecurityDomain.builder().withName(NAME).withDefaultRealm(APPLICATION_FS_REALM)
                .withPermissionMapper(NAME).withRealms(SecurityDomainRealm.builder().withRealm(APPLICATION_FS_REALM).build())
                .withRoleMapper(NAME).build());

        elements.add(SimpleConfigurableSaslServerFactory.builder().withName(NAME).withSaslServerFactory("elytron")
                .addFilter(SaslFilter.builder().withPatternFilter(saslMechanismName).build()).build());
        elements.add(SimpleSaslAuthenticationFactory.builder().withName(NAME).withSaslServerFactory(NAME)
                .withSecurityDomain(NAME)
                .addMechanismConfiguration(MechanismConfiguration.builder().withMechanismName(saslMechanismName).build())
                .build());

        elements.add(SimpleSocketBinding.builder().withName(NAME).withPort(PORT_NATIVE).build());
        elements.add(SimpleMgmtNativeInterface.builder().withSocketBinding(NAME).withSaslAuthenticationFactory(NAME).build());
        return elements;
    }

}

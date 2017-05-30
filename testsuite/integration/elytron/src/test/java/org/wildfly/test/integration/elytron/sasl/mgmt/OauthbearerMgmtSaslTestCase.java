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

import java.util.List;

import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.test.security.common.AbstractElytronSetupTask;
import org.wildfly.test.security.common.elytron.ConfigurableElement;

/**
 * Tests OAUTHBEARER SASL mechanism used for management interface.
 *
 * @author Josef Cacek
 */
@RunWith(Arquillian.class)
@ServerSetup({ OauthbearerMgmtSaslTestCase.ServerSetup.class })
public class OauthbearerMgmtSaslTestCase extends AbstractMgmtSaslTestBase {

    private static final String MECHANISM = "OAUTHBEARER";

    /**
     * Expired token
     *
     * <pre>
     * {
     *   "iss": "issuer.wildfly.org",
     *   "sub": "elytron@wildfly.org",
     *   "exp": 1136073599,  // 20051231235959Z
     *   "iat": 1104537599,  // 20041231235959Z
     *   "aud": "jwt"
     * }
     * </pre>
     */
    protected static final String TOKEN_EXPIRED = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIud2lsZGZseS5vcmciLCJzdWIiOiJlbHl0cm9uQHdpbGRmbHkub3JnIiwiZXhwIjoxMTM2MDczNTk5LCJpYXQiOjExMDQ1Mzc1OTksImF1ZCI6Imp3dCJ9.cQmi4smytz15Yd1UIkkaLZPbw5f3p-o_MZpVxTJoDYo";
    /**
     * Expired token
     *
     * <pre>
     * {
     *   "iss": "issuer.wildfly.org",
     *   "sub": "elytron@wildfly.org",
     *   "nbf": 2082758340,  // 20351231235900Z
     *   "exp": 2082758399,  // 20351231235959Z
     *   "aud": "jwt"
     * }
     * </pre>
     */
    protected static final String TOKEN_NOT_BEFORE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIud2lsZGZseS5vcmciLCJzdWIiOiJlbHl0cm9uQHdpbGRmbHkub3JnIiwibmJmIjoyMDgyNzU4MzQwLCJleHAiOjIwODI3NTgzOTksImF1ZCI6Imp3dCJ9.d2_pD0vAVNp4cCB3uXJxJ589rrEf4vtrFtoa8C_oYZY";

    @Override
    protected String getMechanism() {
        return MECHANISM;
    }

    /**
     * Tests that client is able to use mechanism when server allows it.
     */
    @Test
    public void testCorrectMechanismPasses() throws Exception {
        assertMechPassWhoAmI(MECHANISM, "jwt");
    }

    @Test
    @Ignore("ELY-1194")
    public void testExpiredToken() throws Exception {
        AuthenticationContext.empty()
                .with(MatchRule.ALL,
                        AuthenticationConfiguration.EMPTY.allowAllSaslMechanisms()
                                .useBearerTokenCredential(new BearerTokenCredential(TOKEN_EXPIRED)))
                .run(() -> assertAuthenticationFails());
    }

    @Test
    @Ignore("ELY-1194")
    public void testNotYetValidToken() throws Exception {
        AuthenticationContext.empty()
        .with(MatchRule.ALL,
                AuthenticationConfiguration.EMPTY.allowAllSaslMechanisms()
                .useBearerTokenCredential(new BearerTokenCredential(TOKEN_NOT_BEFORE)))
        .run(() -> assertAuthenticationFails());
    }

    /**
     * Setup task which configures Elytron security domains and remoting connectors for this test.
     */
    public static class ServerSetup extends AbstractElytronSetupTask {

        @Override
        protected ConfigurableElement[] getConfigurableElements() {
            List<ConfigurableElement> elements = createConfigurableElementsForSaslMech(MECHANISM);
            return elements.toArray(new ConfigurableElement[elements.size()]);
        }
    }
}

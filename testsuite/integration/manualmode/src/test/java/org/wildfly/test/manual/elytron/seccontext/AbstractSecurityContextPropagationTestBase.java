/*
 * Copyright 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.test.manual.elytron.seccontext;

import static java.util.concurrent.TimeUnit.SECONDS;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.jboss.as.test.integration.security.common.Utils.REDIRECT_STRATEGY;
import static org.jboss.as.test.shared.integration.ejb.security.PermissionUtils.createPermissionsXmlAsset;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.JAR_ENTRY_EJB;
import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.SERVER1;
import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.SERVER2;
import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.WAR_ENTRY_SERVLET_BASIC;
import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.WAR_ENTRY_SERVLET_BEARER_TOKEN;
import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.WAR_ENTRY_SERVLET_FORM;
import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.WAR_WHOAMI;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.SocketPermission;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.List;
import java.util.concurrent.Callable;

import javax.ejb.EJBAccessException;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.arquillian.container.test.api.ContainerController;
import org.jboss.arquillian.container.test.api.Deployer;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.cli.CommandContext;
import org.jboss.as.cli.CommandLineException;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.network.NetworkUtils;
import org.jboss.as.test.integration.domain.management.util.DomainTestUtils;
import org.jboss.as.test.integration.management.util.CLIOpResult;
import org.jboss.as.test.integration.management.util.CLITestUtil;
import org.jboss.as.test.integration.management.util.MgmtOperationException;
import org.jboss.as.test.integration.management.util.ServerReload;
import org.jboss.as.test.integration.security.common.SecurityTestConstants;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.as.test.shared.TestSuiteEnvironment;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.permission.ElytronPermission;
import org.wildfly.security.sasl.SaslMechanismSelector;

/**
 * Tests for testing (re)authentication and security identity propagation between 2 servers. Test scenarios use following
 * configuration:
 *
 * <pre>
 * EJB client -> Entry bean on server1 -> WhoAmI bean on server 2
 * (ignored) EJB client -> Entry bean on server1 -> WhoAmI servlet on server 2
 * HTTP client -> Entry servlet (BASIC authn) on server1 -> WhoAmI bean on server 2
 * HTTP client -> Entry servlet (FORM authn) on server1 -> WhoAmI bean on server 2
 * </pre>
 *
 * The Entry bean uses Elytron API to configure security context for outbound calls (e.g. identity forwarding, reauthentication,
 * ...).
 *
 * @author Josef Cacek
 */
@RunWith(Arquillian.class)
@RunAsClient
public abstract class AbstractSecurityContextPropagationTestBase {

    private static final ServerHolder server1 = new ServerHolder(SERVER1, TestSuiteEnvironment.getServerAddress(), 0);
    private static final ServerHolder server2 = new ServerHolder(SERVER2, TestSuiteEnvironment.getServerAddressNode1(), 100);

    private static final Package PACKAGE = AbstractSecurityContextPropagationTestBase.class.getPackage();

    private static final Encoder B64_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final String JWT_HEADER_B64 = B64_ENCODER
            .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

    @ArquillianResource
    private static volatile ContainerController containerController;

    @ArquillianResource
    private static volatile Deployer deployer;

    /**
     * Creates deployment with Entry bean - to be placed on the first server.
     */
    @Deployment(name = JAR_ENTRY_EJB, managed = false, testable = false)
    @TargetsContainer(SERVER1)
    public static Archive<?> createEntryBeanDeployment() {
        return ShrinkWrap.create(JavaArchive.class, JAR_ENTRY_EJB + ".jar")
                .addClasses(EntryBean.class, EntryBeanSFSB.class, Entry.class, WhoAmI.class, ReAuthnType.class,
                        SeccontextUtil.class)
                .addAsManifestResource(createPermissionsXmlAsset(new ElytronPermission("authenticate"),
                        new ElytronPermission("getPrivateCredentials"),
                        new ElytronPermission("getSecurityDomain"),
                        new SocketPermission(TestSuiteEnvironment.getServerAddressNode1() + ":8180", "connect,resolve")
                        ),
                        "permissions.xml")
                .addAsManifestResource(Utils.getJBossEjb3XmlAsset("seccontext-entry"), "jboss-ejb3.xml");
    }

    /**
     * Creates deployment with Entry servlet and BASIC authentication.
     */
    @Deployment(name = WAR_ENTRY_SERVLET_BASIC, managed = false, testable = false)
    @TargetsContainer(SERVER1)
    public static Archive<?> createEntryServletBasicAuthnDeployment() {
        return createEntryServletDeploymentBase(WAR_ENTRY_SERVLET_BASIC)
                .addAsWebInfResource(new StringAsset(SecurityTestConstants.WEB_XML_BASIC_AUTHN), "web.xml");
    }

    /**
     * Creates deployment with Entry servlet and FORM authentication.
     */
    @Deployment(name = WAR_ENTRY_SERVLET_FORM, managed = false, testable = false)
    @TargetsContainer(SERVER1)
    public static Archive<?> createEntryServletFormAuthnDeployment() {
        return createEntryServletDeploymentBase(WAR_ENTRY_SERVLET_FORM)
                .addAsWebInfResource(PACKAGE, "web-form-authn.xml", "web.xml")
                .addAsWebResource(PACKAGE, "login.html", "login.html").addAsWebResource(PACKAGE, "error.html", "error.html");
    }

    /**
     * Creates deployment with Entry servlet and BEARER authentication.
     */
    @Deployment(name = WAR_ENTRY_SERVLET_BEARER_TOKEN, managed = false, testable = false)
    @TargetsContainer(SERVER1)
    public static Archive<?> createEntryServletBearerAuthnDeployment() {
        return createEntryServletDeploymentBase(WAR_ENTRY_SERVLET_BEARER_TOKEN).addAsWebInfResource(PACKAGE,
                "web-token-authn.xml", "web.xml");
    }

    /**
     * Creates deployment with WhoAmI bean and servlet - to be placed on the second server.
     */
    @Deployment(name = WAR_WHOAMI, managed = false, testable = false)
    @TargetsContainer(SERVER2)
    public static Archive<?> createEjbClientDeployment() {
        return ShrinkWrap.create(WebArchive.class, WAR_WHOAMI + ".war")
                .addClasses(WhoAmIBean.class, WhoAmIBeanSFSB.class, WhoAmI.class, WhoAmIServlet.class)
                .addAsWebInfResource(Utils.getJBossWebXmlAsset("seccontext-web"), "jboss-web.xml")
                .addAsWebInfResource(new StringAsset(SecurityTestConstants.WEB_XML_BASIC_AUTHN), "web.xml")
                .addAsWebInfResource(Utils.getJBossEjb3XmlAsset("seccontext-whoami"), "jboss-ejb3.xml");
    }

    /**
     * Set or reset configuration of test servers.
     */
    @Before
    public void before() throws CommandLineException, IOException, MgmtOperationException {
        server1.resetContainerConfiguration(JAR_ENTRY_EJB, WAR_ENTRY_SERVLET_BASIC, WAR_ENTRY_SERVLET_FORM,
                WAR_ENTRY_SERVLET_BEARER_TOKEN);
        server2.resetContainerConfiguration(WAR_WHOAMI);
    }

    @AfterClass
    public static void afterClass() throws IOException {
        server1.shutDown();
        server2.shutDown();
    }

    @Test
    public void testAuthCtxPasses() throws Exception {
        String[] doubleWhoAmI = SeccontextUtil.switchIdentity("entry", "entry",
                getDoubleWhoAmICallable(ReAuthnType.AUTHENTICATION_CONTEXT), ReAuthnType.AUTHENTICATION_CONTEXT);
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertArrayEquals("Unexpected principal names returned from doubleWhoAmI", new String[] { "entry", "whoami" },
                doubleWhoAmI);
    }

    @Test
    public void testClientInsufficientRoles() throws Exception {
        try {
            SeccontextUtil.switchIdentity("whoami", "whoami", getDoubleWhoAmICallable(ReAuthnType.AUTHENTICATION_CONTEXT),
                    ReAuthnType.AUTHENTICATION_CONTEXT);
            fail("Calling Entry bean must fail when user without required roles is used");
        } catch (EJBAccessException e) {
            // OK - expected
        }
    }

    @Test
    public void testAuthCtxWrongUserFail() throws Exception {
        String[] doubleWhoAmI = SeccontextUtil.switchIdentity("entry", "entry",
                getDoubleWhoAmICallable(ReAuthnType.AUTHENTICATION_CONTEXT, "doesntexist", "whoami"),
                ReAuthnType.AUTHENTICATION_CONTEXT);
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertEquals("The result of doubleWhoAmI() has wrong lenght", 2, doubleWhoAmI.length);
        assertEquals("entry", doubleWhoAmI[0]);
        assertThat(doubleWhoAmI[1], isEjbAuthenticationError());
    }

    @Test
    public void testAuthCtxWrongPasswdFail() throws Exception {
        String[] doubleWhoAmI = SeccontextUtil.switchIdentity("entry", "entry",
                getDoubleWhoAmICallable(ReAuthnType.AUTHENTICATION_CONTEXT, "whoami", "wrongpass"),
                ReAuthnType.AUTHENTICATION_CONTEXT);
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertEquals("The result of doubleWhoAmI() has wrong lenght", 2, doubleWhoAmI.length);
        assertEquals("entry", doubleWhoAmI[0]);
        assertThat(doubleWhoAmI[1], isEjbAuthenticationError());
    }

    @Test
    public void testForwardedIdentityPasses() throws Exception {
        String[] doubleWhoAmI = SeccontextUtil.switchIdentity("admin", "admin",
                getDoubleWhoAmICallable(ReAuthnType.FORWARDED_IDENTITY, null, null), ReAuthnType.AUTHENTICATION_CONTEXT);
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertArrayEquals("Unexpected principal names returned from doubleWhoAmI", new String[] { "admin", "admin" },
                doubleWhoAmI);
    }

    @Test
    public void testForwardedIdentityInsufficientRolesFails() throws Exception {
        String[] doubleWhoAmI = SeccontextUtil.switchIdentity("entry", "entry",
                getDoubleWhoAmICallable(ReAuthnType.FORWARDED_IDENTITY, null, null), ReAuthnType.AUTHENTICATION_CONTEXT);
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertEquals("The result of doubleWhoAmI() has wrong lenght", 2, doubleWhoAmI.length);
        assertEquals("entry", doubleWhoAmI[0]);
        assertThat(doubleWhoAmI[1], isEjbAccessException());
    }

    @Test
    public void testSecurityDomainAuthenticateWithoutForwarding() throws Exception {
        String[] doubleWhoAmI = SeccontextUtil.switchIdentity("entry", "entry",
                getDoubleWhoAmICallable(ReAuthnType.SECURITY_DOMAIN_AUTHENTICATE), ReAuthnType.AUTHENTICATION_CONTEXT);
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertEquals("The result of doubleWhoAmI() has wrong lenght", 2, doubleWhoAmI.length);
        assertEquals("entry", doubleWhoAmI[0]);
        assertThat(doubleWhoAmI[1], isEjbAuthenticationError());
    }

    @Test
    public void testSecurityDomainAuthenticateWrongPassFails() throws Exception {
        String[] doubleWhoAmI = SeccontextUtil.switchIdentity("entry", "entry",
                getDoubleWhoAmICallable(ReAuthnType.SECURITY_DOMAIN_AUTHENTICATE, "doesntexist", "whoami"),
                ReAuthnType.AUTHENTICATION_CONTEXT);
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertEquals("The result of doubleWhoAmI() has wrong lenght", 2, doubleWhoAmI.length);
        assertEquals("entry", doubleWhoAmI[0]);
        assertThat(doubleWhoAmI[1], isEvidenceVerificationError());
    }

    @Test
    public void testSecurityDomainAuthenticateForwardedPasses() throws Exception {
        String[] doubleWhoAmI = SeccontextUtil.switchIdentity("entry", "entry",
                getDoubleWhoAmICallable(ReAuthnType.SECURITY_DOMAIN_AUTHENTICATE_FORWARDED),
                ReAuthnType.AUTHENTICATION_CONTEXT);
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertArrayEquals("Unexpected principal names returned from doubleWhoAmI", new String[] { "entry", "whoami" },
                doubleWhoAmI);
    }

    @Test
    public void testSecurityDomainAuthenticateForwardedWrongPasswordFails() throws Exception {
        String[] doubleWhoAmI = SeccontextUtil.switchIdentity("entry", "entry",
                getDoubleWhoAmICallable(ReAuthnType.SECURITY_DOMAIN_AUTHENTICATE_FORWARDED, "doesntexist", "whoami"),
                ReAuthnType.AUTHENTICATION_CONTEXT);
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertEquals("The result of doubleWhoAmI() has wrong lenght", 2, doubleWhoAmI.length);
        assertEquals("entry", doubleWhoAmI[0]);
        assertThat(doubleWhoAmI[1], isEvidenceVerificationError());
    }

    @Test
    public void testOauthbearerPropagationPasses() throws Exception {
        String[] doubleWhoAmI = AuthenticationContext.empty()
                .with(MatchRule.ALL,
                        AuthenticationConfiguration.empty().setSaslMechanismSelector(SaslMechanismSelector.ALL)
                                .useBearerTokenCredential(new BearerTokenCredential(createJwtToken("admin"))))
                .runCallable(getDoubleWhoAmICallable(ReAuthnType.FORWARDED_IDENTITY, null, null));
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertArrayEquals("Unexpected principal names returned from doubleWhoAmI", new String[] { "admin", "admin" },
                doubleWhoAmI);
    }

    @Test
    public void testOauthbearerPropagationInsufficientRolesFails() throws Exception {
        String[] doubleWhoAmI = AuthenticationContext.empty()
                .with(MatchRule.ALL,
                        AuthenticationConfiguration.empty().setSaslMechanismSelector(SaslMechanismSelector.ALL)
                                .useBearerTokenCredential(new BearerTokenCredential(createJwtToken("entry"))))
                .runCallable(getDoubleWhoAmICallable(ReAuthnType.FORWARDED_IDENTITY, null, null));
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertEquals("The result of doubleWhoAmI() has wrong lenght", 2, doubleWhoAmI.length);
        assertEquals("entry", doubleWhoAmI[0]);
        assertThat(doubleWhoAmI[1], isEjbAccessException());
    }

    @Test
    public void testClientOauthbearerInsufficientRolesFails() throws Exception {
        try {
            AuthenticationContext.empty()
                    .with(MatchRule.ALL,
                            AuthenticationConfiguration.empty().setSaslMechanismSelector(SaslMechanismSelector.ALL)
                                    .useBearerTokenCredential(new BearerTokenCredential(createJwtToken("whoami"))))
                    .runCallable(getDoubleWhoAmICallable(ReAuthnType.FORWARDED_IDENTITY, null, null));
            fail("Call to the protected bean should fail");
        } catch (EJBAccessException e) {
            // OK - expected
        }
    }

    /**
     * Test credentials propagation from HTTP BASIC authentication.
     */
    @Test
    public void testServletBasicToEjbForwardedIdentity() throws Exception {
        final URL entryServletUrl = getEntryServletUrl(WAR_ENTRY_SERVLET_BASIC, null, null, ReAuthnType.FORWARDED_IDENTITY);

        // call with user who doesn't have sufficient roles on Servlet
        Utils.makeCallWithBasicAuthn(entryServletUrl, "entry", "entry", SC_FORBIDDEN);

        // call with user who doesn't have sufficient roles on EJB
        assertThat(Utils.makeCallWithBasicAuthn(entryServletUrl, "servlet", "servlet", SC_OK), isEjbAccessException());

        // call with user who has all necessary roles
        assertEquals("Unexpected username returned", "admin",
                Utils.makeCallWithBasicAuthn(entryServletUrl, "admin", "admin", SC_OK));

        // call (again) with the user who doesn't have sufficient roles on EJB
        assertThat(Utils.makeCallWithBasicAuthn(entryServletUrl, "servlet", "servlet", SC_OK), isEjbAccessException());
    }

    /**
     * Test reauthentication through authentication context API when using HTTP BASIC authentication.
     */
    @Test
    public void testServletBasicToEjbAuthenticationContext() throws Exception {
        // call with users who have all necessary roles
        assertEquals("Unexpected username returned", "whoami",
                Utils.makeCallWithBasicAuthn(
                        getEntryServletUrl(WAR_ENTRY_SERVLET_BASIC, "whoami", "whoami", ReAuthnType.AUTHENTICATION_CONTEXT),
                        "servlet", "servlet", SC_OK));

        // call with another user who have sufficient roles on EJB
        assertEquals("Unexpected username returned", "admin",
                Utils.makeCallWithBasicAuthn(
                        getEntryServletUrl(WAR_ENTRY_SERVLET_BASIC, "admin", "admin", ReAuthnType.AUTHENTICATION_CONTEXT),
                        "servlet", "servlet", SC_OK));

        // call with another servlet user
        assertEquals("Unexpected username returned", "whoami",
                Utils.makeCallWithBasicAuthn(
                        getEntryServletUrl(WAR_ENTRY_SERVLET_BASIC, "whoami", "whoami", ReAuthnType.AUTHENTICATION_CONTEXT),
                        "admin", "admin", SC_OK));

        // call with wrong EJB username
        assertThat(Utils.makeCallWithBasicAuthn(
                getEntryServletUrl(WAR_ENTRY_SERVLET_BASIC, "xadmin", "admin", ReAuthnType.AUTHENTICATION_CONTEXT), "admin",
                "admin", SC_OK), isEjbAuthenticationError());

        // call with wrong EJB password
        assertThat(Utils.makeCallWithBasicAuthn(
                getEntryServletUrl(WAR_ENTRY_SERVLET_BASIC, "admin", "adminx", ReAuthnType.AUTHENTICATION_CONTEXT), "admin",
                "admin", SC_OK), isEjbAuthenticationError());
    }

    /**
     * Test credentials propagation from HTTP FORM authentication when the servlet which needs propagation is not the
     * authenticated one (i.e. it's requested after the user is already authenticated).
     */
    @Test
    public void testServletFormWhoAmIFirst() throws Exception {
        final URL entryServletUrl = getEntryServletUrl(WAR_ENTRY_SERVLET_FORM, null, null, ReAuthnType.FORWARDED_IDENTITY);
        final URL whoAmIServletUrl = new URL(
                server1.getApplicationHttpUrl() + "/" + WAR_ENTRY_SERVLET_FORM + WhoAmIServlet.SERVLET_PATH);

        try (final CloseableHttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(REDIRECT_STRATEGY).build()) {
            assertEquals("Unexpected result from WhoAmIServlet", "admin",
                    doHttpRequestFormAuthn(httpClient, whoAmIServletUrl, true, "admin", "admin", SC_OK));
            assertEquals("Unexpected result from EntryServlet", "admin", doHttpRequest(httpClient, entryServletUrl, SC_OK));
        }

        // do the call without sufficient role in EJB (server2)
        try (final CloseableHttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(REDIRECT_STRATEGY).build()) {
            assertEquals("Unexpected result from WhoAmIServlet", "servlet",
                    doHttpRequestFormAuthn(httpClient, whoAmIServletUrl, true, "servlet", "servlet", SC_OK));
            assertThat("Unexpected result from EntryServlet", doHttpRequest(httpClient, entryServletUrl, SC_OK),
                    isEjbAccessException());
        }
    }

    /**
     * Test credentials propagation from HTTP FORM authentication when the servlet which needs propagation is the authenticated
     * one.
     */
    @Test
    public void testServletFormEntryFirst() throws Exception {
        final URL entryServletUrl = getEntryServletUrl(WAR_ENTRY_SERVLET_FORM, null, null, ReAuthnType.FORWARDED_IDENTITY);
        final URL whoAmIServletUrl = new URL(
                server1.getApplicationHttpUrl() + "/" + WAR_ENTRY_SERVLET_FORM + WhoAmIServlet.SERVLET_PATH);

        try (final CloseableHttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(REDIRECT_STRATEGY).build()) {
            assertEquals("Unexpected result from EntryServlet", "admin",
                    doHttpRequestFormAuthn(httpClient, entryServletUrl, true, "admin", "admin", SC_OK));
            assertEquals("Unexpected result from WhoAmIServlet", "admin", doHttpRequest(httpClient, whoAmIServletUrl, SC_OK));
        }

        // do the call without sufficient role in EJB (server2)
        try (final CloseableHttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(REDIRECT_STRATEGY).build()) {
            assertThat("Unexpected result from EntryServlet",
                    doHttpRequestFormAuthn(httpClient, entryServletUrl, true, "servlet", "servlet", SC_OK),
                    isEjbAccessException());
            assertEquals("Unexpected result from WhoAmIServlet", "servlet", doHttpRequest(httpClient, whoAmIServletUrl, SC_OK));
        }
    }

    /**
     * Test credentials propagation from HTTP BEARER_TOKEN authentication when the servlet which needs propagation is not the
     * authenticated one (i.e. it's requested after the user is already authenticated).
     */
    @Test
    public void testServletBearerTokenWhoAmIFirst() throws Exception {
        final URL entryServletUrl = getEntryServletUrl(WAR_ENTRY_SERVLET_BEARER_TOKEN, null, null,
                ReAuthnType.FORWARDED_IDENTITY);
        final URL whoAmIServletUrl = new URL(
                server1.getApplicationHttpUrl() + "/" + WAR_ENTRY_SERVLET_BEARER_TOKEN + WhoAmIServlet.SERVLET_PATH);

        try (final CloseableHttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(REDIRECT_STRATEGY).build()) {
            assertEquals("Unexpected result from WhoAmIServlet", "admin",
                    doHttpRequestTokenAuthn(httpClient, whoAmIServletUrl, createJwtToken("admin"), SC_OK));
            assertEquals("Unexpected result from EntryServlet", "admin", doHttpRequest(httpClient, entryServletUrl, SC_OK));
        }

        // do the call without sufficient role in EJB (server2)
        try (final CloseableHttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(REDIRECT_STRATEGY).build()) {
            assertEquals("Unexpected result from WhoAmIServlet", "servlet",
                    doHttpRequestTokenAuthn(httpClient, whoAmIServletUrl, createJwtToken("servlet"), SC_OK));
            assertThat("Unexpected result from EntryServlet", doHttpRequest(httpClient, entryServletUrl, SC_OK),
                    isEjbAccessException());
        }
    }

    /**
     * Test credentials propagation from HTTP BEARER_TOKEN authentication when the servlet which needs propagation is the
     * authenticated one.
     */
    @Test
    public void testServletBearerTokenEntryFirst() throws Exception {
        final URL entryServletUrl = getEntryServletUrl(WAR_ENTRY_SERVLET_BEARER_TOKEN, null, null,
                ReAuthnType.FORWARDED_IDENTITY);
        final URL whoAmIServletUrl = new URL(
                server1.getApplicationHttpUrl() + "/" + WAR_ENTRY_SERVLET_BEARER_TOKEN + WhoAmIServlet.SERVLET_PATH);

        try (final CloseableHttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(REDIRECT_STRATEGY).build()) {
            assertEquals("Unexpected result from EntryServlet", "admin",
                    doHttpRequestTokenAuthn(httpClient, entryServletUrl, createJwtToken("admin"), SC_OK));
            assertEquals("Unexpected result from WhoAmIServlet", "admin", doHttpRequest(httpClient, whoAmIServletUrl, SC_OK));
        }

        // do the call without sufficient role in EJB (server2)
        try (final CloseableHttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(REDIRECT_STRATEGY).build()) {
            assertThat("Unexpected result from EntryServlet",
                    doHttpRequestTokenAuthn(httpClient, entryServletUrl, createJwtToken("servlet"), SC_OK),
                    isEjbAccessException());
            assertEquals("Unexpected result from WhoAmIServlet", "servlet", doHttpRequest(httpClient, whoAmIServletUrl, SC_OK));
        }
    }

    /**
     * Test identity forwarding for HttpURLConnection calls.
     */
    @Test
    @Ignore("JBEAP-12340")
    public void testHttpPropagation() throws Exception {
        Callable<String> callable = getEjbToServletCallable(ReAuthnType.FORWARDED_IDENTITY, null, null);
        String servletResponse = SeccontextUtil.switchIdentity("admin", "admin", callable, ReAuthnType.AUTHENTICATION_CONTEXT);
        assertEquals("Unexpected principal name returned from servlet call", "admin", servletResponse);
    }

    /**
     * Tests if re-authentication works for HttpURLConnection calls.
     */
    @Test
    @Ignore("JBEAP-12340")
    public void testHttpReauthn() throws Exception {
        Callable<String> callable = getEjbToServletCallable(ReAuthnType.AUTHENTICATION_CONTEXT, "servlet", "servlet");
        String servletResponse = SeccontextUtil.switchIdentity("admin", "admin", callable, ReAuthnType.AUTHENTICATION_CONTEXT);
        assertEquals("Unexpected principal name returned from servlet call", "servlet", servletResponse);
    }

    /**
     * Tests propagation when user propagated to HttpURLConnection has insufficient roles.
     */
    @Test
    @Ignore("JBEAP-12340")
    public void testHttpReauthnInsufficientRoles() throws Exception {
        Callable<String> callable = getEjbToServletCallable(ReAuthnType.AUTHENTICATION_CONTEXT, "whoami", "whoami");
        String servletResponse = SeccontextUtil.switchIdentity("entry", "entry", callable, ReAuthnType.AUTHENTICATION_CONTEXT);
        assertThat(servletResponse, allOf(startsWith("java.io.IOException"), containsString("403")));
    }

    /**
     * Tests propagation when user propagated to HttpURLConnection has insufficient roles.
     */
    @Test
    public void testHttpReauthnWrongPass() throws Exception {
        Callable<String> callable = getEjbToServletCallable(ReAuthnType.AUTHENTICATION_CONTEXT, "servlet", "whoami");
        String servletResponse = SeccontextUtil.switchIdentity("entry", "entry", callable, ReAuthnType.AUTHENTICATION_CONTEXT);
        assertThat(servletResponse, allOf(startsWith("java.io.IOException"), containsString("401")));
    }

    /**
     * Returns true if the stateful Entry bean variant should be used by the tests. False otherwise.
     */
    protected abstract boolean isEntryStateful();

    /**
     * Returns true if the stateful WhoAmI bean variant should be used by the tests. False otherwise.
     */
    protected abstract boolean isWhoAmIStateful();

    /**
     * Do HTTP GET request with given client.
     *
     * @param httpClient
     * @param url
     * @param expectedStatus expected status coe
     * @return response body
     */
    private String doHttpRequest(final CloseableHttpClient httpClient, final URL url, int expectedStatus)
            throws URISyntaxException, IOException, ClientProtocolException, UnsupportedEncodingException {
        return doHttpRequestFormAuthn(httpClient, url, false, null, null, expectedStatus);
    }

    /**
     * Do HTTP request using given client with possible FORM authentication.
     *
     * @param httpClient client instance
     * @param url URL to make request to
     * @param loginFormExpected flag which says if login (FORM) is expected, if true username and password arguments are used to
     *        login.
     * @param username user to fill into the login form
     * @param password password to fill into the login form
     * @param expectedStatus expected status code
     * @return response body
     */
    private String doHttpRequestFormAuthn(final CloseableHttpClient httpClient, final URL url, boolean loginFormExpected,
            String username, String password, int expectedStatus)
            throws URISyntaxException, IOException, ClientProtocolException, UnsupportedEncodingException {
        HttpGet httpGet = new HttpGet(url.toURI());

        HttpResponse response = httpClient.execute(httpGet);

        HttpEntity entity = response.getEntity();
        assertNotNull(entity);
        String responseBody = EntityUtils.toString(entity);
        if (loginFormExpected) {
            assertThat("Login page was expected", responseBody, containsString("j_security_check"));
            assertEquals("HTTP OK response for login page was expected", SC_OK, response.getStatusLine().getStatusCode());

            // We should now login with the user name and password
            HttpPost httpPost = new HttpPost(
                    server1.getApplicationHttpUrl() + "/" + WAR_ENTRY_SERVLET_FORM + "/j_security_check");

            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
            nvps.add(new BasicNameValuePair("j_username", username));
            nvps.add(new BasicNameValuePair("j_password", password));

            httpPost.setEntity(new UrlEncodedFormEntity(nvps, "UTF-8"));

            response = httpClient.execute(httpPost);
            entity = response.getEntity();
            assertNotNull(entity);
            responseBody = EntityUtils.toString(entity);
        } else {
            assertThat("Login page was not expected", responseBody, not(containsString("j_security_check")));
        }
        assertEquals("Unexpected status code", expectedStatus, response.getStatusLine().getStatusCode());
        return responseBody;
    }

    /**
     * Do HTTP request using given client with BEARER_TOKEN authentication.
     *
     * @param httpClient client instance
     * @param url URL to make request to
     * @param token bearer token
     * @param expectedStatus expected status code
     * @return response body
     */
    private String doHttpRequestTokenAuthn(final CloseableHttpClient httpClient, final URL url, String token,
            int expectedStatusCode)
            throws URISyntaxException, IOException, ClientProtocolException, UnsupportedEncodingException {
        final HttpGet httpGet = new HttpGet(url.toURI());

        HttpResponse response = httpClient.execute(httpGet);
        int statusCode = response.getStatusLine().getStatusCode();
        if (HttpServletResponse.SC_UNAUTHORIZED != statusCode || StringUtils.isEmpty(token)) {
            assertEquals("Unexpected HTTP response status code.", expectedStatusCode, statusCode);
            return EntityUtils.toString(response.getEntity());
        }
        Header[] authenticateHeaders = response.getHeaders("WWW-Authenticate");
        assertTrue("Expected WWW-Authenticate header was not present in the HTTP response",
                authenticateHeaders != null && authenticateHeaders.length > 0);
        boolean bearerAuthnHeaderFound = false;
        for (Header header : authenticateHeaders) {
            final String headerVal = header.getValue();
            if (headerVal != null && headerVal.startsWith("Bearer")) {
                bearerAuthnHeaderFound = true;
                break;
            }
        }
        assertTrue("WWW-Authenticate response header didn't request expected Bearer token authentication",
                bearerAuthnHeaderFound);
        HttpEntity entity = response.getEntity();
        if (entity != null)
            EntityUtils.consume(entity);

        httpGet.addHeader("Authorization", "Bearer " + token);
        response = httpClient.execute(httpGet);
        statusCode = response.getStatusLine().getStatusCode();
        assertEquals("Unexpected status code returned after the authentication.", expectedStatusCode, statusCode);
        return EntityUtils.toString(response.getEntity());
    }

    /**
     * Creates callable for executing {@link Entry#doubleWhoAmI(String, String, ReAuthnType, String)} as "whoami" user.
     *
     * @param type reauthentication reauthentication type used within the doubleWhoAmI
     * @return Callable
     */
    private Callable<String[]> getDoubleWhoAmICallable(final ReAuthnType type) {
        return getDoubleWhoAmICallable(type, "whoami", "whoami");
    }

    /**
     * Creates callable for executing {@link Entry#doubleWhoAmI(String, String, ReAuthnType, String)} as given user.
     *
     * @param type reauthentication re-authentication type used within the doubleWhoAmI
     * @param username
     * @param password
     * @return
     */
    private Callable<String[]> getDoubleWhoAmICallable(final ReAuthnType type, final String username, final String password) {
        return () -> {
            final Entry bean = SeccontextUtil.lookup(
                    SeccontextUtil.getRemoteEjbName(JAR_ENTRY_EJB, "EntryBean", Entry.class.getName(), isEntryStateful()),
                    server1.getApplicationRemotingUrl());
            final String server2Url = server2.getApplicationRemotingUrl();
            return bean.doubleWhoAmI(username, password, type, server2Url, isWhoAmIStateful());
        };
    }

    private Callable<String> getEjbToServletCallable(final ReAuthnType type, final String username, final String password) {
        return () -> {
            final Entry bean = SeccontextUtil.lookup(
                    SeccontextUtil.getRemoteEjbName(JAR_ENTRY_EJB, "EntryBean", Entry.class.getName(), isEntryStateful()),
                    server1.getApplicationRemotingUrl());
            final String servletUrl = server2.getApplicationHttpUrl() + "/" + WAR_WHOAMI + WhoAmIServlet.SERVLET_PATH;
            return bean.readUrl(username, password, type, new URL(servletUrl));
        };
    }

    private static org.hamcrest.Matcher<java.lang.String> isEjbAuthenticationError() {
        // different behavior for stateless and stateful beans
        // is reported under https://issues.jboss.org/browse/JBEAP-12439
        return anyOf(startsWith("javax.ejb.NoSuchEJBException: EJBCLIENT000079"),
                startsWith("javax.naming.CommunicationException: EJBCLIENT000062"),
                containsString("JBREM000308"),
                containsString("javax.security.sasl.SaslException: Authentication failed"));
    }

    private static org.hamcrest.Matcher<java.lang.String> isEvidenceVerificationError() {
        return startsWith("java.lang.SecurityException: ELY01151");
    }

    private static org.hamcrest.Matcher<java.lang.String> isEjbAccessException() {
        return startsWith("javax.ejb.EJBAccessException");
    }

    private String createJwtToken(String userName) {
        String jwtPayload = String.format("{" //
                + "\"iss\": \"issuer.wildfly.org\"," //
                + "\"sub\": \"elytron@wildfly.org\"," //
                + "\"exp\": 2051222399," //
                + "\"aud\": \"%1$s\"," //
                + "\"groups\": [\"%1$s\"]" //
                + "}", userName);
        return JWT_HEADER_B64 + "." + B64_ENCODER.encodeToString(jwtPayload.getBytes(StandardCharsets.UTF_8)) + ".";
    }

    private URL getEntryServletUrl(String warName, String username, String password, ReAuthnType type) throws IOException {
        final StringBuilder sb = new StringBuilder(server1.getApplicationHttpUrl() + "/" + warName + EntryServlet.SERVLET_PATH);
        addQueryParam(sb, EntryServlet.PARAM_USERNAME, username);
        addQueryParam(sb, EntryServlet.PARAM_PASSWORD, password);
        addQueryParam(sb, EntryServlet.PARAM_STATEFULL, String.valueOf(isWhoAmIStateful()));
        addQueryParam(sb, EntryServlet.PARAM_CREATE_SESSION, String.valueOf(true));
        addQueryParam(sb, EntryServlet.PARAM_REAUTHN_TYPE, type.name());
        addQueryParam(sb, EntryServlet.PARAM_PROVIDER_URL, server2.getApplicationRemotingUrl());
        return new URL(sb.toString());
    }

    private static void addQueryParam(StringBuilder sb, String paramName, String paramValue) {
        final String encodedPair = Utils.encodeQueryParam(paramName, paramValue);
        if (encodedPair != null) {
            sb.append(sb.indexOf("?") < 0 ? "?" : "&").append(encodedPair);
        }
    }

    /**
     * Creates deployment base with Entry servlet. It doesn't contain web.xml and related resources if needed (e.g. login page).
     */
    private static WebArchive createEntryServletDeploymentBase(String name) {
        return ShrinkWrap.create(WebArchive.class, name + ".war")
                .addClasses(EntryServlet.class, WhoAmIServlet.class, WhoAmI.class, ReAuthnType.class, SeccontextUtil.class)
                .addAsManifestResource(createPermissionsXmlAsset(new ElytronPermission("authenticate"),
                        new ElytronPermission("getPrivateCredentials"), new ElytronPermission("getSecurityDomain"),
                        new SocketPermission(TestSuiteEnvironment.getServerAddressNode1() + ":8180", "connect,resolve")),
                        "permissions.xml")
                .addAsWebInfResource(Utils.getJBossWebXmlAsset("seccontext-web"), "jboss-web.xml");
    }

    private static class ServerHolder {
        private final String name;
        private final String host;
        private final int portOffset;
        private volatile ModelControllerClient client;
        private volatile CommandContext commandCtx;
        private volatile ByteArrayOutputStream consoleOut = new ByteArrayOutputStream();

        private volatile String snapshot;

        public ServerHolder(String name, String host, int portOffset) {
            this.name = name;
            this.host = host;
            this.portOffset = portOffset;
        }

        public void resetContainerConfiguration(String... deployments)
                throws CommandLineException, IOException, MgmtOperationException {
            if (!containerController.isStarted(name)) {
                containerController.start(name);
                client = ModelControllerClient.Factory.create(host, getManagementPort());
                commandCtx = CLITestUtil.getCommandContext(host, getManagementPort(), null, consoleOut, -1);
                commandCtx.connectController();
                readSnapshot();

                if (snapshot == null) {
                    // configure each server just once
                    createPropertyFile();
                    final File cliFIle = File.createTempFile("seccontext-", ".cli");
                    try (FileOutputStream fos = new FileOutputStream(cliFIle)) {
                        IOUtils.copy(
                                AbstractSecurityContextPropagationTestBase.class.getResourceAsStream("seccontext-setup.cli"),
                                fos);
                    }
                    runBatch(cliFIle);
                    cliFIle.delete();
                    reload();

                    for (String deployment : deployments) {
                        deployer.deploy(deployment);
                    }

                    takeSnapshot();
                }
            }
        }

        public void shutDown() throws IOException {
            if (containerController.isStarted(name)) {
                // deployer.undeploy(name);
                commandCtx.terminateSession();
                client.close();
                containerController.stop(name);
            }
        }

        public int getManagementPort() {
            return 9990 + portOffset;
        }

        public int getApplicationPort() {
            return 8080 + portOffset;
        }

        public String getApplicationHttpUrl() throws IOException {
            return "http://" + NetworkUtils.formatPossibleIpv6Address(host) + ":" + getApplicationPort();
        }

        public String getApplicationRemotingUrl() throws IOException {
            return "remote+" + getApplicationHttpUrl();
        }

        /**
         * Sends command line to CLI.
         *
         * @param line specifies the command line.
         * @param ignoreError if set to false, asserts that handling the line did not result in a
         *        {@link org.jboss.as.cli.CommandLineException}.
         *
         * @return true if the CLI is in a non-error state following handling the line
         */
        public boolean sendLine(String line, boolean ignoreError) {
            consoleOut.reset();
            if (ignoreError) {
                commandCtx.handleSafe(line);
                return commandCtx.getExitCode() == 0;
            } else {
                try {
                    commandCtx.handle(line);
                } catch (CommandLineException e) {
                    StringWriter stackTrace = new StringWriter();
                    e.printStackTrace(new PrintWriter(stackTrace));
                    Assert.fail(String.format("Failed to execute line '%s'%n%s", line, stackTrace.toString()));
                }
            }
            return true;
        }

        /**
         * Runs given CLI script file as a batch.
         *
         * @param batchFile CLI file to run in batch
         * @return true if CLI returns Success
         */
        public boolean runBatch(File batchFile) throws IOException {
            sendLine("run-batch --file=\"" + batchFile.getAbsolutePath() + "\" -v", false);
            if (consoleOut.size() <= 0) {
                return false;
            }
            return new CLIOpResult(ModelNode.fromStream(new ByteArrayInputStream(consoleOut.toByteArray())))
                    .isIsOutcomeSuccess();
        }

        private void takeSnapshot() throws IOException, MgmtOperationException {
            DomainTestUtils.executeForResult(Util.createOperation("take-snapshot", null), client);
            readSnapshot();
        }

        private void readSnapshot() throws IOException, MgmtOperationException {
            ModelNode namesNode = DomainTestUtils.executeForResult(Util.createOperation("list-snapshots", null), client)
                    .get("names");
            if (namesNode == null || namesNode.getType() != ModelType.LIST) {
                throw new IllegalStateException("Unexpected return value from :list-snaphot operation: " + namesNode);
            }
            List<ModelNode> snapshots = namesNode.asList();
            if (!snapshots.isEmpty()) {
                snapshot = namesNode.get(snapshots.size() - 1).asString();
            }
        }

        private void reload() {
            ModelNode operation = Util.createOperation("reload", null);
            ServerReload.executeReloadAndWaitForCompletion(client, operation, (int) SECONDS.toMillis(90), host,
                    getManagementPort());
        }

        /**
         * Create single property file with users and/or roles in standalone server config directory. It will be used for
         * property-realm configuration (see {@code seccontext-setup.cli} script)
         */
        private void createPropertyFile() throws IOException {
            sendLine("/core-service=platform-mbean/type=runtime:read-attribute(name=system-properties)", false);
            assertTrue(consoleOut.size() > 0);
            ModelNode node = ModelNode.fromStream(new ByteArrayInputStream(consoleOut.toByteArray()));
            String configDirPath = node.get(ModelDescriptionConstants.RESULT).get("jboss.server.config.dir").asString();
            Files.write(Paths.get(configDirPath, "seccontext.properties"),
                    Utils.createUsersFromRoles("admin", "servlet", "entry", "whoami").getBytes(StandardCharsets.ISO_8859_1));
        }
    }
}

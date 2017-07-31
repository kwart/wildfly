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
import static org.hamcrest.CoreMatchers.startsWith;
import static org.jboss.as.controller.client.helpers.ClientConstants.SERVER_CONFIG;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.SERVER1;
import static org.wildfly.test.manual.elytron.seccontext.SeccontextUtil.SERVER2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.concurrent.Callable;

import org.apache.commons.io.IOUtils;
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
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Tests for testing (re)authentication and security identity propagation between 2 servers. Test scenarios use following
 * configuration:
 *
 * <pre>
 * EJB client -> Entry bean on server1 -> WhoAmI bean on server 2
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

    private static ServerHolder server1 = new ServerHolder(SERVER1, TestSuiteEnvironment.getServerAddress(), 0);
    private static ServerHolder server2 = new ServerHolder(SERVER2, TestSuiteEnvironment.getServerAddressNode1(), 100);

    @ArquillianResource
    private static ContainerController containerController;

    @ArquillianResource
    private static Deployer deployer;

    @Deployment(name = SERVER1, managed = false, testable = false)
    @TargetsContainer(SERVER1)
    public static Archive<?> createEntryBeanDeployment() {
        return ShrinkWrap.create(JavaArchive.class, SERVER1 + ".jar")
                .addClasses(EntryBean.class, EntryBeanSFSB.class, Entry.class, WhoAmI.class, ReAuthnType.class,
                        SeccontextUtil.class)
                .addAsManifestResource(Utils.getJBossEjb3XmlAsset("seccontext-entry"), "jboss-ejb3.xml");
    }

    @Deployment(name = SERVER2, managed = false, testable = false)
    @TargetsContainer(SERVER2)
    public static Archive<?> createEjbClientDeployment() {
        return ShrinkWrap.create(WebArchive.class, SERVER2 + ".war")
                .addClasses(WhoAmIBean.class, WhoAmIBeanSFSB.class, WhoAmI.class, WhoAmIServlet.class)
                .addAsWebInfResource(Utils.getJBossWebXmlAsset("seccontext-whoami"), "jboss-web.xml")
                .addAsWebInfResource(new StringAsset(SecurityTestConstants.WEB_XML_BASIC_AUTHN), "web.xml")
                .addAsManifestResource(Utils.getJBossEjb3XmlAsset("seccontext-whoami"), "jboss-ejb3.xml");
    }

    /**
     * Set or reset configuration of test servers.
     */
    @Before
    public void before() throws CommandLineException, IOException, MgmtOperationException {
        server1.resetContainerConfiguration();
        server2.resetContainerConfiguration();
    }

    @AfterClass
    public static void afterClass() throws IOException {
        server1.shutDown();
        server2.shutDown();
    }

    @Test
    public void testAuthCtxWrongUserFail() throws Exception {
        String[] doubleWhoAmI = SeccontextUtil.switchIdentity("entry", "entry",
                getDoubleWhoAmICallable(ReAuthnType.AUTHENTICATION_CONTEXT, "doesntexist", "whoami"),
                ReAuthnType.AUTHENTICATION_CONTEXT);
        assertNotNull("The entryBean.doubleWhoAmI() should return not-null instance", doubleWhoAmI);
        assertEquals("The result of doubleWhoAmI() has wrong lenght", 2, doubleWhoAmI.length);
        assertEquals("entry", doubleWhoAmI[0]);
        assertThat(doubleWhoAmI[1], startsWith("javax.naming.CommunicationException: EJBCLIENT000062"));
    }

    protected abstract boolean isEntryStateful();

    protected abstract boolean isWhoAmIStateful();

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
                    SeccontextUtil.getRemoteEjbName(SERVER1, "EntryBean", Entry.class.getName(), isEntryStateful()),
                    server1.getApplicationRemotingUrl());
            final String server2Url = server2.getApplicationRemotingUrl();
            return bean.doubleWhoAmI(username, password, type, server2Url, isWhoAmIStateful());
        };
    }

    private static class ServerHolder {
        private String name;
        private String host;
        private int portOffset;
        private ModelControllerClient client;
        private CommandContext commandCtx;
        private ByteArrayOutputStream consoleOut = new ByteArrayOutputStream();

        private String snapshot;

        public ServerHolder(String name, String host, int portOffset) {
            this.name = name;
            this.host = host;
            this.portOffset = portOffset;
        }

        public void resetContainerConfiguration() throws CommandLineException, IOException, MgmtOperationException {
            if (!containerController.isStarted(name)) {
                containerController.start(name);
                client = ModelControllerClient.Factory.create(host, getManagementPort());
                commandCtx = CLITestUtil.getCommandContext(host, getManagementPort(), null, consoleOut, -1);
                commandCtx.connectController();
                readSnapshot();
            }

            if (snapshot == null) {
                final File cliFIle = File.createTempFile("seccontext-", ".cli");
                try (FileOutputStream fos = new FileOutputStream(cliFIle)) {
                    IOUtils.copy(AbstractSecurityContextPropagationTestBase.class.getResourceAsStream("seccontext-setup.cli"),
                            fos);
                }
                runBatch(cliFIle);
                cliFIle.delete();
                reload();
                // deployment name is the same as the container name in this test case
                deployer.deploy(name);

                takeSnapshot();
            } else {
                reloadToSnapshot();
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

        private void reloadToSnapshot() {
            ModelNode operation = Util.createOperation("reload", null);
            operation.get(SERVER_CONFIG).set(snapshot);
            ServerReload.executeReloadAndWaitForCompletion(client, operation, (int) SECONDS.toMillis(90), host,
                    getManagementPort());
        }

        private void reload() {
            ModelNode operation = Util.createOperation("reload", null);
            ServerReload.executeReloadAndWaitForCompletion(client, operation, (int) SECONDS.toMillis(90), host,
                    getManagementPort());
        }
    }
}

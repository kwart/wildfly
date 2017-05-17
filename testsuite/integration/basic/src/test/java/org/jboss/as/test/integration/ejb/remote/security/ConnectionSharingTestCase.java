/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013, Red Hat, Inc., and individual contributors
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
package org.jboss.as.test.integration.ejb.remote.security;

import java.io.IOException;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.junit.InSequence;
import org.jboss.as.network.NetworkUtils;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.naming.client.WildFlyInitialContextFactory;

/**
 * Regression test for handling protocol name in the shared remoting connection.
 *
 * @author Josef Cacek
 */
@RunWith(Arquillian.class)
@RunAsClient
public class ConnectionSharingTestCase {

    private static final String HOST = NetworkUtils.formatPossibleIpv6Address(System.getProperty("node0", "localhost"));

    private static final String APPLICATION_NAME = "connection-sharing-test";

    /**
     * Creates a deployment application for this test.
     *
     * @return
     * @throws IOException
     */
    @Deployment(testable = false)
    public static JavaArchive createDeployment() throws IOException {
        return ShrinkWrap.create(JavaArchive.class, APPLICATION_NAME + ".jar") //
                .addClasses(SecurityInformation.class, SecuredBean.class);
    }

    @Test
    @InSequence(0)
    public void testContextProviderUrl() throws Exception {
        final Properties properties = new Properties();
        properties.put(Context.INITIAL_CONTEXT_FACTORY, WildFlyInitialContextFactory.class.getName());
        properties.put(Context.PROVIDER_URL, "remote+http://" + HOST + ":8080");

        assertBeanCallWithContextProperties(properties, "$local");
    }

    @Test
    @InSequence(1)
    public void testRemoteConnection() throws Exception {
        final Properties properties = new Properties();
        properties.put("remote.connectionprovider.create.options.org.xnio.Options.SSL_ENABLED", "false");
        properties.put("remote.connection.default.connect.options.org.xnio.Options.SASL_DISALLOWED_MECHANISMS",
                "JBOSS-LOCAL-USER");
        properties.put("remote.connections", "default");
        properties.put("remote.connection.default.host", HOST);
        properties.put("remote.connection.default.port", "8080");

        // JBREM000202: Abrupt close on Remoting connection:
        // properties.put("remote.connection.default.protocol", "remote");

        // doesn't work:
        // properties.put("remote.connection.default.protocol", "remote+http");

        // this one works:
        // properties.put("remote.connection.default.protocol", "http-remoting");

        properties.put("remote.connection.default.username", "guest");
        properties.put("remote.connection.default.password", "guest");
        properties.put(Context.URL_PKG_PREFIXES, "org.jboss.ejb.client.naming");

        assertBeanCallWithContextProperties(properties, "guest");
    }

    private void assertBeanCallWithContextProperties(final Properties properties, String expectedPrincipal)
            throws NamingException {
        final InitialContext initialCtx = new InitialContext(properties);
        try {
            SecurityInformation bean = (SecurityInformation) initialCtx.lookup("ejb:/" + APPLICATION_NAME + "/"
                    + SecuredBean.class.getSimpleName() + "!" + SecurityInformation.class.getName());
            Assert.assertEquals("Principal name doesn't match", expectedPrincipal, bean.getPrincipalName());
        } finally {
            initialCtx.close();
        }
    }

}

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
package org.wildfly.test.security.common.other;

import static org.wildfly.test.security.common.ModelNodeUtil.setIfNotNull;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.dmr.ModelNode;
import org.wildfly.test.security.common.elytron.ConfigurableElement;

/**
 * Configuration for /core-service=management/management-interface=native-interface.
 *
 * @author Josef Cacek
 */
public class SimpleMgmtNativeInterface implements ConfigurableElement {

    private static final PathAddress PATH_NATIVE_INTERFACE = PathAddress.pathAddress().append("core-service", "management").append("management-interface", "native-interface");
    
    private final String saslAuthenticationFactory;
    private final String socketBinding;

    private SimpleMgmtNativeInterface(Builder builder) {
        this.saslAuthenticationFactory = builder.saslAuthenticationFactory;
        this.socketBinding = builder.socketBinding;
    }

    @Override
    public void create(ModelControllerClient client, CLIWrapper cli) throws Exception {
        ModelNode op = Util
                .createAddOperation(PATH_NATIVE_INTERFACE);
        setIfNotNull(op, "sasl-authentication-factory", saslAuthenticationFactory);
        setIfNotNull(op, "socket-binding", socketBinding);

        Utils.applyUpdate(op, client);
    }

    @Override
    public void remove(ModelControllerClient client, CLIWrapper cli) throws Exception {
        Utils.applyUpdate(Util.createRemoveOperation(PATH_NATIVE_INTERFACE), client);
    }

    @Override
    public String getName() {
        return "management-interface=native-interface";
    }

    /**
     * Creates builder to build {@link SimpleMgmtNativeInterface}.
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }


    /**
     * Builder to build {@link SimpleMgmtNativeInterface}.
     */
    public static final class Builder {
        private String saslAuthenticationFactory;
        private String socketBinding;

        private Builder() {
        }

        public Builder withSaslAuthenticationFactory(String saslAuthenticationFactory) {
            this.saslAuthenticationFactory = saslAuthenticationFactory;
            return this;
        }

        public Builder withSocketBinding(String socketBinding) {
            this.socketBinding = socketBinding;
            return this;
        }

        public SimpleMgmtNativeInterface build() {
            return new SimpleMgmtNativeInterface(this);
        }
    }


}

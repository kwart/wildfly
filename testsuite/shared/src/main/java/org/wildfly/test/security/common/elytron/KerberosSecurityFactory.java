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

package org.wildfly.test.security.common.elytron;

import static org.wildfly.test.security.common.ModelNodeUtil.setIfNotNull;

import java.util.Map;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.dmr.ModelNode;

/**
 * Elytron 'kerberos-security-factory' configuration helper.
 *
 * @author Josef Cacek
 */
public class KerberosSecurityFactory extends AbstractConfigurableElement {

    private final Boolean debug;
    private final String[] mechanismNames;
    private final String[] mechanismOids;
    private final Integer minimumRemainingLifetime;
    private final Boolean obtainKerberosTicket;
    private final Map<String, String> options;
    private final String principal;
    private final Integer requestLifetime;
    private final Boolean server;
    private final Boolean wrapGssCredential;
    private final Path path;

    private KerberosSecurityFactory(Builder builder) {
        super(builder);
        this.debug = builder.debug;
        this.mechanismNames = builder.mechanismNames;
        this.mechanismOids = builder.mechanismOids;
        this.minimumRemainingLifetime = builder.minimumRemainingLifetime;
        this.obtainKerberosTicket = builder.obtainKerberosTicket;
        this.options = builder.options;
        this.principal = builder.principal;
        this.requestLifetime = builder.requestLifetime;
        this.server = builder.server;
        this.wrapGssCredential = builder.wrapGssCredential;
        this.path = builder.path;
    }

    @Override
    public void create(ModelControllerClient client, CLIWrapper cli) throws Exception {
        ModelNode op = Util.createAddOperation(
                PathAddress.pathAddress().append("subsystem", "elytron").append("kerberos-security-factory", name));
        setIfNotNull(op, "debug", debug);
        setIfNotNull(op, "mechanism-names", mechanismNames);
        setIfNotNull(op, "mechanism-oids", mechanismOids);
        setIfNotNull(op, "minimum-remaining-lifetime", minimumRemainingLifetime);
        setIfNotNull(op, "obtain-kerberos-ticket", obtainKerberosTicket);
        setIfNotNull(op, "obtain-kerberos-ticket", obtainKerberosTicket);
        setIfNotNull(op, "options", options);
        setIfNotNull(op, "principal", principal);
        setIfNotNull(op, "request-lifetime", requestLifetime);
        setIfNotNull(op, "server", server);
        setIfNotNull(op, "wrap-gss-credential", wrapGssCredential);
        setIfNotNull(op, "principal", principal);
        setIfNotNull(op, "path", path.getPath());
        setIfNotNull(op, "relative-to", path.getRelativeTo());

        Utils.applyUpdate(op, client);
    }

    @Override
    public void remove(ModelControllerClient client, CLIWrapper cli) throws Exception {
        Utils.applyUpdate(
                Util.createRemoveOperation(
                        PathAddress.pathAddress().append("subsystem", "elytron").append("kerberos-security-factory", name)),
                client);
    }

    /**
     * Creates builder to build {@link KerberosSecurityFactory}.
     *
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder to build {@link KerberosSecurityFactory}.
     */
    public static final class Builder extends AbstractConfigurableElement.Builder<Builder> {
        private Boolean debug;
        private String[] mechanismNames;
        private String[] mechanismOids;
        private Integer minimumRemainingLifetime;
        private Boolean obtainKerberosTicket;
        private Map<String, String> options;
        private String principal;
        private Integer requestLifetime;
        private Boolean server;
        private Boolean wrapGssCredential;
        private Path path;

        private Builder() {
        }

        public Builder withDebug(Boolean debug) {
            this.debug = debug;
            return this;
        }

        public Builder withMechanismNames(String[] mechanismNames) {
            this.mechanismNames = mechanismNames;
            return this;
        }

        public Builder withMechanismOids(String[] mechanismOids) {
            this.mechanismOids = mechanismOids;
            return this;
        }

        public Builder withMinimumRemainingLifetime(Integer minimumRemainingLifetime) {
            this.minimumRemainingLifetime = minimumRemainingLifetime;
            return this;
        }

        public Builder withObtainKerberosTicket(Boolean obtainKerberosTicket) {
            this.obtainKerberosTicket = obtainKerberosTicket;
            return this;
        }

        public Builder withOptions(Map<String, String> options) {
            this.options = options;
            return this;
        }

        public Builder withPrincipal(String principal) {
            this.principal = principal;
            return this;
        }

        public Builder withRequestLifetime(Integer requestLifetime) {
            this.requestLifetime = requestLifetime;
            return this;
        }

        public Builder withServer(Boolean server) {
            this.server = server;
            return this;
        }

        public Builder withWrapGssCredential(Boolean wrapGssCredential) {
            this.wrapGssCredential = wrapGssCredential;
            return this;
        }

        public Builder withPath(Path path) {
            this.path = path;
            return this;
        }

        public KerberosSecurityFactory build() {
            return new KerberosSecurityFactory(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }

}

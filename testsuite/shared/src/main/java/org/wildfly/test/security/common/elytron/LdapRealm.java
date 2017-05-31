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

import java.util.Objects;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.dmr.ModelNode;

/**
 * Elytron 'ldap-realm' configuration.
 *
 * @author Josef Cacek
 */
public class LdapRealm extends AbstractConfigurableElement implements SecurityRealm {

    private final Boolean allowBlankPassword;
    private final String dirContext;
    private final Boolean directVerification;
    private final IdentityMapping identityMapping;

    private LdapRealm(Builder builder) {
        super(builder);
        this.allowBlankPassword = builder.allowBlankPassword;
        this.dirContext = Objects.requireNonNull(builder.dirContext, "The 'dir-context' has to be provided.");
        this.directVerification = builder.directVerification;
        this.identityMapping = Objects.requireNonNull(builder.identityMapping, "The 'identity-mapping' has to be provided.");
    }

    @Override
    public void create(ModelControllerClient client, CLIWrapper cli) throws Exception {
        ModelNode op = Util
                .createAddOperation(PathAddress.pathAddress().append("subsystem", "elytron").append("ldap-realm", name));
        op.get("dir-context").set(dirContext);
        setIfNotNull(op, "allow-blank-password", allowBlankPassword);
        setIfNotNull(op, "direct-verification", directVerification);
        setIfNotNull(op, "identity-mapping", identityMapping);
        Utils.applyUpdate(op, client);
    }

    @Override
    public void remove(ModelControllerClient client, CLIWrapper cli) throws Exception {
        Utils.applyUpdate(
                Util.createRemoveOperation(PathAddress.pathAddress().append("subsystem", "elytron").append("ldap-realm", name)),
                client);
    }

    /**
     * Creates builder to build {@link LdapRealm}.
     *
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder to build {@link LdapRealm}.
     */
    public static final class Builder extends AbstractConfigurableElement.Builder<Builder> {
        private Boolean allowBlankPassword;
        private String dirContext;
        private Boolean directVerification;
        private IdentityMapping identityMapping;

        private Builder() {
        }

        public Builder withAllowBlankPassword(Boolean allowBlankPassword) {
            this.allowBlankPassword = allowBlankPassword;
            return this;
        }

        public Builder withDirContext(String dirContext) {
            this.dirContext = dirContext;
            return this;
        }

        public Builder withDirectVerification(Boolean directVerification) {
            this.directVerification = directVerification;
            return this;
        }

        public Builder withIdentityMapping(IdentityMapping identityMapping) {
            this.identityMapping = identityMapping;
            return this;
        }

        public LdapRealm build() {
            return new LdapRealm(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}

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

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.client.helpers.Operations;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.dmr.ModelNode;

/**
 * Elytron configurator for trusted-domains attribute in a security-domain.
 *
 * @author Josef Cacek
 */
public class TrustedDomainsConfigurator extends AbstractConfigurableElement {

    private final String[] trustedSecurityDomains;

    private ModelNode originalDomains;

    private TrustedDomainsConfigurator(Builder builder) {
        super(builder);
        this.trustedSecurityDomains = builder.trustedSecurityDomains;
    }

    @Override
    public void create(ModelControllerClient client, CLIWrapper cli) throws Exception {
        final PathAddress domainAddress = PathAddress.pathAddress().append("subsystem", "elytron").append("security-domain",
                name);
        ModelNode op = Util.createEmptyOperation("read-attribute", domainAddress);
        op.get("name").set("trusted-security-domains");
        ModelNode result = client.execute(op);
        if (Operations.isSuccessfulOutcome(result)) {
            result = Operations.readResult(result);
            originalDomains = result.isDefined() ? result : null;
        } else {
            throw new RuntimeException("Reading existing value of trusted-security-domains attribute failed: "
                    + Operations.getFailureDescription(result));
        }

        op = Util.createEmptyOperation("write-attribute", domainAddress);
        op.get("name").set("trusted-security-domains");
        for (String domain : trustedSecurityDomains) {
            op.get("value").add(domain);
        }
        Utils.applyUpdate(op, client);
    }

    @Override
    public void remove(ModelControllerClient client, CLIWrapper cli) throws Exception {
        final PathAddress domainAddress = PathAddress.pathAddress().append("subsystem", "elytron").append("security-domain",
                name);
        ModelNode op = Util.createEmptyOperation("write-attribute", domainAddress);
        op.get("name").set("trusted-security-domains");
        if (originalDomains != null) {
            op.get("value").set(originalDomains);
        }
        Utils.applyUpdate(op, client);
        originalDomains = null;
    }

    /**
     * Creates builder to build {@link TrustedDomainsConfigurator}.
     *
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder to build {@link TrustedDomainsConfigurator}.
     */
    public static final class Builder extends AbstractConfigurableElement.Builder<Builder> {
        private String[] trustedSecurityDomains;

        private Builder() {
        }

        public Builder withTrustedSecurityDomains(String... trustedSecurityDomains) {
            this.trustedSecurityDomains = trustedSecurityDomains;
            return this;
        }

        public TrustedDomainsConfigurator build() {
            return new TrustedDomainsConfigurator(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}

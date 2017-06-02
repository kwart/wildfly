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
 * Elytron 'regex-principal-transformer' configuration.
 *
 * @author Josef Cacek
 */
public class RegexPrincipalTransformer extends AbstractConfigurableElement {

    private final String pattern;
    private final String replacement;
    private final Boolean replaceAll;

    private RegexPrincipalTransformer(Builder builder) {
        super(builder);
        this.pattern = Objects.requireNonNull(builder.pattern, "Pattern attribute has to be provided");
        this.replacement = Objects.requireNonNull(builder.replacement, "Replacement attribute has to be provided");
        this.replaceAll = builder.replaceAll;
    }

    @Override
    public void create(ModelControllerClient client, CLIWrapper cli) throws Exception {
        ModelNode op = Util.createAddOperation(
                PathAddress.pathAddress().append("subsystem", "elytron").append("regex-principal-transformer", name));
        setIfNotNull(op, "pattern", pattern);
        setIfNotNull(op, "replacement", replacement);
        setIfNotNull(op, "replace-all", replaceAll);
        Utils.applyUpdate(op, client);
    }

    @Override
    public void remove(ModelControllerClient client, CLIWrapper cli) throws Exception {
        Utils.applyUpdate(
                Util.createRemoveOperation(
                        PathAddress.pathAddress().append("subsystem", "elytron").append("regex-principal-transformer", name)),
                client);
    }

    /**
     * Creates builder to build {@link RegexPrincipalTransformer}.
     *
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder to build {@link RegexPrincipalTransformer}.
     */
    public static final class Builder extends AbstractConfigurableElement.Builder<Builder> {

        private String pattern;
        private String replacement;
        private Boolean replaceAll;

        private Builder() {
        }

        public Builder withPattern(String pattern) {
            this.pattern = pattern;
            return this;
        }

        public Builder withReplacement(String replacement) {
            this.replacement = replacement;
            return this;
        }

        public Builder withReplaceAll(Boolean replaceAll) {
            this.replaceAll = replaceAll;
            return this;
        }

        public RegexPrincipalTransformer build() {
            return new RegexPrincipalTransformer(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}

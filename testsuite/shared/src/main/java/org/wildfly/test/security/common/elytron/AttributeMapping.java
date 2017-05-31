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

import static org.wildfly.test.security.common.ModelNodeUtil.*;

import org.jboss.dmr.ModelNode;
import org.wildfly.test.security.common.elytron.ModelNodeConvertable;

/**
 * Represantation of an attribute-mapping configuration in ldap-realm/identity-mapping.
 *
 * @author Josef Cacek
 */
public class AttributeMapping implements ModelNodeConvertable {

    private final String from;
    private final String to;
    private final String reference;
    private final String filter;
    private final String filterBaseDn;
    private final Boolean searchRecursive;
    private final Integer roleRecursion;
    private final String roleRecursionName;
    private final String extractRdn;


    private AttributeMapping(Builder builder) {
        this.from = builder.from;
        this.to = builder.to;
        this.reference = builder.reference;
        this.filter = builder.filter;
        this.filterBaseDn = builder.filterBaseDn;
        this.searchRecursive = builder.searchRecursive;
        this.roleRecursion = builder.roleRecursion;
        this.roleRecursionName = builder.roleRecursionName;
        this.extractRdn = builder.extractRdn;
    }

    @Override
    public ModelNode toModelNode() {
        ModelNode modelNode = new ModelNode();
        setIfNotNull(modelNode, "from", from);
        setIfNotNull(modelNode, "to", to);
        setIfNotNull(modelNode, "reference", reference);
        setIfNotNull(modelNode, "filter", filter);
        setIfNotNull(modelNode, "filter-base-dn", filterBaseDn);
        setIfNotNull(modelNode, "search-recursive", searchRecursive);
        setIfNotNull(modelNode, "role-recursion", roleRecursion);
        setIfNotNull(modelNode, "role-recursion-name", roleRecursionName);
        setIfNotNull(modelNode, "extract-rdn", extractRdn);
        return modelNode;
    }

    /**
     * Creates builder to build {@link AttributeMapping}.
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }
    /**
     * Builder to build {@link AttributeMapping}.
     */
    public static final class Builder {
        private String from;
        private String to;
        private String reference;
        private String filter;
        private String filterBaseDn;
        private Boolean searchRecursive;
        private Integer roleRecursion;
        private String roleRecursionName;
        private String extractRdn;

        private Builder() {
        }

        public Builder withFrom(String from) {
            this.from = from;
            return this;
        }

        public Builder withTo(String to) {
            this.to = to;
            return this;
        }

        public Builder withReference(String reference) {
            this.reference = reference;
            return this;
        }

        public Builder withFilter(String filter) {
            this.filter = filter;
            return this;
        }

        public Builder withFilterBaseDn(String filterBaseDn) {
            this.filterBaseDn = filterBaseDn;
            return this;
        }

        public Builder withSearchRecursive(Boolean searchRecursive) {
            this.searchRecursive = searchRecursive;
            return this;
        }

        public Builder withRoleRecursion(Integer roleRecursion) {
            this.roleRecursion = roleRecursion;
            return this;
        }

        public Builder withRoleRecursionName(String roleRecursionName) {
            this.roleRecursionName = roleRecursionName;
            return this;
        }

        public Builder withExtractRdn(String extractRdn) {
            this.extractRdn = extractRdn;
            return this;
        }

        public AttributeMapping build() {
            return new AttributeMapping(this);
        }
    }
}

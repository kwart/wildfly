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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.jboss.dmr.ModelNode;

/**
 * Represantation of identity-mapping configuration in ldap-realm.
 *
 * @author Josef Cacek
 */
public class IdentityMapping implements ModelNodeConvertable {

    private final String rdnIdentifier;
    private final Boolean useRecursiveSearch;
    private final String searchBaseDn;
    private final AttributeMapping[] attributeMapping;
    private final String filterName;
    private final String iteratorFilter;
    private final String newIdentityParentDn;
    private final NameValue[] newIdentityAttributes;
    private final UserPasswordMapper userPasswordMapper;
    private final OtpCredentialMapper otpCredentialMapper;
    private final X509CredentialMapper x509CredentialMapper;


    private IdentityMapping(Builder builder) {
        this.rdnIdentifier = Objects.requireNonNull(builder.rdnIdentifier, "The rdn-identifier has to be provided in identity-mapping.");
        this.useRecursiveSearch = builder.useRecursiveSearch;
        this.searchBaseDn = builder.searchBaseDn;
        this.attributeMapping = builder.attributeMapping.toArray(new AttributeMapping[builder.attributeMapping.size()]);
        this.filterName = builder.filterName;
        this.iteratorFilter = builder.iteratorFilter;
        this.newIdentityParentDn = builder.newIdentityParentDn;
        this.newIdentityAttributes = builder.newIdentityAttributes;
        this.userPasswordMapper = builder.userPasswordMapper;
        this.otpCredentialMapper = builder.otpCredentialMapper;
        this.x509CredentialMapper = builder.x509CredentialMapper;
    }

    @Override
    public ModelNode toModelNode() {
        ModelNode modelNode = new ModelNode();
        modelNode.get("rdn-identifier").set(rdnIdentifier);
        setIfNotNull(modelNode, "use-recursive-search", useRecursiveSearch);
        setIfNotNull(modelNode, "search-base-dn", searchBaseDn);
        setIfNotNull(modelNode, "attribute-mapping", attributeMapping);
        setIfNotNull(modelNode, "filter-name", filterName);
        setIfNotNull(modelNode, "iterator-filter", iteratorFilter);
        setIfNotNull(modelNode, "new-identity-parent-dn", newIdentityParentDn);
        setIfNotNull(modelNode, "new-identity-attributes", newIdentityAttributes);
        setIfNotNull(modelNode, "user-password-mapper", userPasswordMapper);
        setIfNotNull(modelNode, "otp-credential-mapper", otpCredentialMapper);
        setIfNotNull(modelNode, "x509-credential-mapper", x509CredentialMapper);
        return modelNode;
    }

    /**
     * Creates builder to build {@link IdentityMapping}.
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }
    /**
     * Builder to build {@link IdentityMapping}.
     */
    public static final class Builder {
        private String rdnIdentifier;
        private Boolean useRecursiveSearch;
        private String searchBaseDn;
        private List<AttributeMapping> attributeMapping = new ArrayList<>();
        private String filterName;
        private String iteratorFilter;
        private String newIdentityParentDn;
        private NameValue[] newIdentityAttributes;
        private UserPasswordMapper userPasswordMapper;
        private OtpCredentialMapper otpCredentialMapper;
        private X509CredentialMapper x509CredentialMapper;

        private Builder() {
        }

        public Builder withRdnIdentifier(String rdnIdentifier) {
            this.rdnIdentifier = rdnIdentifier;
            return this;
        }

        public Builder withUseRecursiveSearch(Boolean useRecursiveSearch) {
            this.useRecursiveSearch = useRecursiveSearch;
            return this;
        }

        public Builder withSearchBaseDn(String searchBaseDn) {
            this.searchBaseDn = searchBaseDn;
            return this;
        }

        public Builder addAttributeMapping(AttributeMapping attributeMapping) {
            this.attributeMapping.add(attributeMapping);
            return this;
        }

        public Builder withFilterName(String filterName) {
            this.filterName = filterName;
            return this;
        }

        public Builder withIteratorFilter(String iteratorFilter) {
            this.iteratorFilter = iteratorFilter;
            return this;
        }

        public Builder withNewIdentityParentDn(String newIdentityParentDn) {
            this.newIdentityParentDn = newIdentityParentDn;
            return this;
        }

        public Builder withNewIdentityAttributes(NameValue... newIdentityAttributes) {
            this.newIdentityAttributes = newIdentityAttributes;
            return this;
        }

        public Builder withUserPasswordMapper(UserPasswordMapper userPasswordMapper) {
            this.userPasswordMapper = userPasswordMapper;
            return this;
        }

        public Builder withOtpCredentialMapper(OtpCredentialMapper otpCredentialMapper) {
            this.otpCredentialMapper = otpCredentialMapper;
            return this;
        }

        public Builder withX509CredentialMapper(X509CredentialMapper x509CredentialMapper) {
            this.x509CredentialMapper = x509CredentialMapper;
            return this;
        }

        public IdentityMapping build() {
            return new IdentityMapping(this);
        }
    }
}

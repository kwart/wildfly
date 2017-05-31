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
 * Represantation of an x509-credential-mapper configuration in ldap-realm/identity-mapping.
 *
 * @author Josef Cacek
 */
public class X509CredentialMapper implements ModelNodeConvertable {

    private final String digestFrom;
    private final String digestAlgorithm;
    private final String certificateFrom;
    private final String serialNumberFrom;
    private final String subjectDnFrom;

    private X509CredentialMapper(Builder builder) {
        this.digestFrom = builder.digestFrom;
        this.digestAlgorithm = builder.digestAlgorithm;
        this.certificateFrom = builder.certificateFrom;
        this.serialNumberFrom = builder.serialNumberFrom;
        this.subjectDnFrom = builder.subjectDnFrom;
    }

    @Override
    public ModelNode toModelNode() {
        ModelNode modelNode = new ModelNode();
        setIfNotNull(modelNode, "digest-from", digestFrom);
        setIfNotNull(modelNode, "digest-algorithm", digestAlgorithm);
        setIfNotNull(modelNode, "certificate-from", certificateFrom);
        setIfNotNull(modelNode, "serial-number-from", serialNumberFrom);
        setIfNotNull(modelNode, "subject-dn-from", subjectDnFrom);
        return modelNode;
    }

    /**
     * Creates builder to build {@link X509CredentialMapper}.
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder to build {@link X509CredentialMapper}.
     */
    public static final class Builder {
        private String digestFrom;
        private String digestAlgorithm;
        private String certificateFrom;
        private String serialNumberFrom;
        private String subjectDnFrom;

        private Builder() {
        }

        public Builder withDigestFrom(String digestFrom) {
            this.digestFrom = digestFrom;
            return this;
        }

        public Builder withDigestAlgorithm(String digestAlgorithm) {
            this.digestAlgorithm = digestAlgorithm;
            return this;
        }

        public Builder withCertificateFrom(String certificateFrom) {
            this.certificateFrom = certificateFrom;
            return this;
        }

        public Builder withSerialNumberFrom(String serialNumberFrom) {
            this.serialNumberFrom = serialNumberFrom;
            return this;
        }

        public Builder withSubjectDnFrom(String subjectDnFrom) {
            this.subjectDnFrom = subjectDnFrom;
            return this;
        }

        public X509CredentialMapper build() {
            return new X509CredentialMapper(this);
        }
    }
}

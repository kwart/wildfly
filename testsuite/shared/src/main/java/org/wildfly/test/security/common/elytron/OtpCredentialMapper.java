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

import java.util.Objects;

import org.jboss.dmr.ModelNode;
import org.wildfly.test.security.common.elytron.ModelNodeConvertable;

/**
 * Represantation of an otp-credential-mapper configuration in ldap-realm/identity-mapping.
 *
 * @author Josef Cacek
 */
public class OtpCredentialMapper implements ModelNodeConvertable {

    private final String algorithmFrom;
    private final String hashFrom;
    private final String seedFrom;
    private final String sequenceFrom;

    private OtpCredentialMapper(Builder builder) {
        this.algorithmFrom = Objects.requireNonNull(builder.algorithmFrom);
        this.hashFrom = Objects.requireNonNull(builder.hashFrom);
        this.seedFrom = Objects.requireNonNull(builder.seedFrom);
        this.sequenceFrom = Objects.requireNonNull(builder.sequenceFrom);
    }

    @Override
    public ModelNode toModelNode() {
        ModelNode modelNode = new ModelNode();
        setIfNotNull(modelNode, "algorithm-from", algorithmFrom);
        setIfNotNull(modelNode, "hash-from", hashFrom);
        setIfNotNull(modelNode, "seed-from", seedFrom);
        setIfNotNull(modelNode, "sequence-from", sequenceFrom);
        return modelNode;
    }

    /**
     * Creates builder to build {@link OtpCredentialMapper}.
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder to build {@link OtpCredentialMapper}.
     */
    public static final class Builder {
        private String algorithmFrom;
        private String hashFrom;
        private String seedFrom;
        private String sequenceFrom;

        private Builder() {
        }

        public Builder withAlgorithmFrom(String algorithmFrom) {
            this.algorithmFrom = algorithmFrom;
            return this;
        }

        public Builder withHashFrom(String hashFrom) {
            this.hashFrom = hashFrom;
            return this;
        }

        public Builder withSeedFrom(String seedFrom) {
            this.seedFrom = seedFrom;
            return this;
        }

        public Builder withSequenceFrom(String sequenceFrom) {
            this.sequenceFrom = sequenceFrom;
            return this;
        }

        public OtpCredentialMapper build() {
            return new OtpCredentialMapper(this);
        }
    }
}

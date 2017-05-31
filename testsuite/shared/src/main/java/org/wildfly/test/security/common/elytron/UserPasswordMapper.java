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
 * Represantation of a user-password-mapper configuration in ldap-realm/identity-mapping.
 *
 * @author Josef Cacek
 */
public class UserPasswordMapper implements ModelNodeConvertable {

    private final String from;
    private final Boolean writable;
    private final Boolean verifiable;

    private UserPasswordMapper(Builder builder) {
        this.from = Objects.requireNonNull(builder.from, "The 'from' attribute has to be provided.");
        this.writable = builder.writable;
        this.verifiable = builder.verifiable;
    }

    @Override
    public ModelNode toModelNode() {
        ModelNode modelNode = new ModelNode();
        setIfNotNull(modelNode, "from", from);
        setIfNotNull(modelNode, "writable", writable);
        setIfNotNull(modelNode, "verifiable", verifiable);
        return modelNode;
    }

    /**
     * Creates builder to build {@link UserPasswordMapper}.
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder to build {@link UserPasswordMapper}.
     */
    public static final class Builder {
        private String from;
        private Boolean writable;
        private Boolean verifiable;

        private Builder() {
        }

        public Builder withFrom(String from) {
            this.from = from;
            return this;
        }

        public Builder withWritable(Boolean writable) {
            this.writable = writable;
            return this;
        }

        public Builder withVerifiable(Boolean verifiable) {
            this.verifiable = verifiable;
            return this;
        }

        public UserPasswordMapper build() {
            return new UserPasswordMapper(this);
        }
    }
}

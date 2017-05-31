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

import java.util.Objects;

import org.jboss.dmr.ModelNode;
import org.wildfly.test.security.common.elytron.ModelNodeConvertable;

/**
 * Representation of name and value attribute pair in domain model.
 *
 * @author Josef Cacek
 */
public class NameValue implements ModelNodeConvertable {

    private final String name;
    private final String value;

    private NameValue(Builder builder) {
        this.name = Objects.requireNonNull(builder.name, "Value of 'name' attribute has to be provided.");
        this.value = Objects.requireNonNull(builder.value, "Value of 'value' attribute has to be provided.");
    }

    @Override
    public ModelNode toModelNode() {
        final ModelNode node = new ModelNode();
        node.get("name").set(name);
        node.get("value").set(value);
        return null;
    }

    /**
     * Creates builder to build {@link NameValue}.
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }

    public static NameValue from(String name, String value) {
        return builder().withName(name).withValue(value).build();
    }

    /**
     * Builder to build {@link NameValue}.
     */
    public static final class Builder {
        private String name;
        private String value;

        private Builder() {
        }

        public Builder withName(String name) {
            this.name = name;
            return this;
        }

        public Builder withValue(String value) {
            this.value = value;
            return this;
        }

        public NameValue build() {
            return new NameValue(this);
        }
    }
}

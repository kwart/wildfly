/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018, Red Hat, Inc., and individual contributors
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

package org.jboss.as.clustering.jgroups.subsystem;

import java.util.function.Consumer;
import java.util.function.UnaryOperator;

import org.jboss.as.clustering.controller.Operations;
import org.jboss.as.clustering.controller.ResourceDescriptor;
import org.jboss.as.clustering.controller.ResourceServiceBuilderFactory;
import org.jboss.as.clustering.jgroups.logging.JGroupsLogger;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.dmr.ModelNode;
import org.jgroups.stack.Protocol;
import org.wildfly.clustering.jgroups.spi.ChannelFactory;

/**
 * Resource definition for legacy protocols.
 * @author Paul Ferraro
 */
public class LegacyProtocolResourceDefinition<P extends Protocol> extends ProtocolResourceDefinition<P> {

    private static class OperationTransformation implements Consumer<ResourceDescriptor>, UnaryOperator<OperationStepHandler>, OperationStepHandler {
        private final String targetName;

        OperationTransformation(String targetName) {
            this.targetName = targetName;
        }

        @Override
        public void accept(ResourceDescriptor descriptor) {
            descriptor.setAddOperationTransformation(this).setOperationTransformation(this);
        }

        @Override
        public OperationStepHandler apply(OperationStepHandler handler) {
            return this;
        }

        @Override
        public void execute(OperationContext context, ModelNode operation) {
            PathAddress address = context.getCurrentAddress();
            JGroupsLogger.ROOT_LOGGER.legacyProtocol(address.getLastElement().getValue(), this.targetName);
            PathAddress targetAddress = address.getParent().append(pathElement(this.targetName));
            Operations.setPathAddress(operation, targetAddress);
            PathAddress targetRegistrationAddress = address.getParent().append(ProtocolResourceDefinition.WILDCARD_PATH);
            String operationName = Operations.getName(operation);
            context.addStep(operation, context.getRootResourceRegistration().getOperationHandler(targetRegistrationAddress, operationName), OperationContext.Stage.MODEL);
        }
    }

    LegacyProtocolResourceDefinition(String name, String targetName, JGroupsModel deprecation, Consumer<ResourceDescriptor> descriptorConfigurator, ResourceServiceBuilderFactory<ChannelFactory> parentBuilderFactory) {
        super(pathElement(name), descriptorConfigurator.andThen(new OperationTransformation(targetName)), null, parentBuilderFactory);
        this.setDeprecated(deprecation.getVersion());
    }
}

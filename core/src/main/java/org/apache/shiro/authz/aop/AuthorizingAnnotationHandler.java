/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authz.aop;

import java.lang.annotation.Annotation;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Delegate;
import org.apache.shiro.aop.AnnotationHandler;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.config.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An AnnotationHandler that executes authorization (access control) behavior based on directive(s) found in a
 * JSR-175 Annotation.
 *
 * @since 0.9.0
 */
public abstract class AuthorizingAnnotationHandler extends AnnotationHandler {

    @Delegate(types = EmptyAuthorizationConfigSwitch.class)
    protected final EmptyAuthorizationConfigPolicy emptyConfigPolicy =
            new EmptyAuthorizationConfigPolicy();

    /**
     * Constructs an <code>AuthorizingAnnotationHandler</code> who processes annotations of the
     * specified type.  Immediately calls <code>super(annotationClass)</code>.
     *
     * @param annotationClass the type of annotation this handler will process.
     */
    public AuthorizingAnnotationHandler(Class<? extends Annotation> annotationClass) {
        super(annotationClass);
    }

    /**
     * Ensures the calling Subject is authorized to execute based on the directive(s) found in the given
     * annotation.
     * <p/>
     * As this is an AnnotationMethodInterceptor, the implementations of this method typically inspect the annotation
     * and perform a corresponding authorization check based.
     *
     * @param a the <code>Annotation</code> to check for performing an authorization check.
     * @throws org.apache.shiro.authz.AuthorizationException if the class/instance/method is not allowed to proceed/execute.
     */
    public abstract void assertAuthorized(Annotation a) throws AuthorizationException;

    /**
     * The part of the policy exposed on filters and handlers: whether empty authorization configuration is
     * rejected instead of only logging a warning.
     */
    public interface EmptyAuthorizationConfigSwitch {
        boolean isFailOnEmptyAuthorizationConfig();
        void setFailOnEmptyAuthorizationConfig(boolean failOnEmptyAuthorizationConfig);
    }

    /**
     * What to do with authorization configuration that names no permissions or roles, such as the {@code perms} and
     * {@code roles} filters without arguments, or {@code @RequiresPermissions({})}.
     * <p/>
     * Such configuration performs no check, which is almost always a mistake. By default a warning is logged and the
     * previous behavior is kept. If
     * {@link #setFailOnEmptyAuthorizationConfig(boolean) failOnEmptyAuthorizationConfig} is set, or the
     * {@value #STRICT_PROPERTY} system property is {@code true}, filters deny access and annotation handlers throw a
     * {@link org.apache.shiro.config.ConfigurationException}.
     *
     * @since 3.0.2
     */
    public static class EmptyAuthorizationConfigPolicy implements EmptyAuthorizationConfigSwitch {
        /**
         * System property that, when {@code true}, makes
         * {@link #isFailOnEmptyAuthorizationConfig() failOnEmptyAuthorizationConfig} default to {@code true}.
         */
        public static final String STRICT_PROPERTY = "shiro.authz.strictEmptyConfig";

        private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizingAnnotationHandler.class);

        /**
         * Whether empty configuration is rejected instead of only logging a warning. Defaults to the value of the
         * {@value #STRICT_PROPERTY} system property, which is {@code false} if unset.
         */
        @Getter
        @Setter
        private boolean failOnEmptyAuthorizationConfig = Boolean.getBoolean(STRICT_PROPERTY);

        /**
         * Returns whether the configuration must be rejected, because it is empty and
         * {@link #isFailOnEmptyAuthorizationConfig()} is set.
         *
         * @param values the configured permissions or roles
         * @return {@code true} if the configuration is empty and must be rejected
         */
        public boolean isEmptyConfigRejected(String[] values) {
            return failOnEmptyAuthorizationConfig && (values == null || values.length == 0);
        }

        /**
         * Logs a warning if the configuration is empty.
         *
         * @param values the configured permissions or roles
         * @param what   describes the configuration, for the log message
         */
        public void warnIfEmptyConfig(String[] values, String what) {
            if (values == null || values.length == 0) {
                LOGGER.warn("{} specifies no permissions or roles, so it {}. Specify at least one.", what,
                        failOnEmptyAuthorizationConfig ? "is rejected" : "performs no check");
            }
        }

        /**
         * Rejects empty configuration by throwing, or else logs a warning if it is empty.
         *
         * @param values         the annotation's {@code value()}
         * @param annotationName the simple name of the annotation, for the message
         * @throws ConfigurationException if the configuration is empty and {@link #isFailOnEmptyAuthorizationConfig()} is set
         */
        public void checkConfigNotEmpty(String[] values, String annotationName) {
            if (isEmptyConfigRejected(values)) {
                throw new ConfigurationException("@" + annotationName + " must specify at least one value");
            }
            warnIfEmptyConfig(values, "@" + annotationName);
        }
    }
}

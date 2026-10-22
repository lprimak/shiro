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

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests that annotations without any roles or permissions only warn by default, and throw when so configured.
 */
public class EmptyAnnotationValueTest extends SecurityManagerTestSupport {

    private static RequiresRoles emptyRoles() {
        return new RequiresRoles() {
            @Override
            public String[] value() {
                return new String[0];
            }

            @Override
            public Logical logical() {
                return Logical.AND;
            }

            @Override
            public Class<? extends Annotation> annotationType() {
                return RequiresRoles.class;
            }
        };
    }

    private static RequiresPermissions emptyPermissions() {
        return new RequiresPermissions() {
            @Override
            public String[] value() {
                return new String[0];
            }

            @Override
            public Logical logical() {
                return Logical.AND;
            }

            @Override
            public Class<? extends Annotation> annotationType() {
                return RequiresPermissions.class;
            }
        };
    }

    @Test
    public void rolesWarnByDefault() throws Throwable {
        RoleAnnotationHandler handler = new RoleAnnotationHandler();
        // anonymous subjects are still rejected by the underlying check, but not because of the configuration
        runWithSubject(subject -> assertThatExceptionOfType(UnauthenticatedException.class)
                .isThrownBy(() -> handler.assertAuthorized(emptyRoles())));
    }

    @Test
    public void rolesThrowWhenStrict() throws Throwable {
        RoleAnnotationHandler handler = new RoleAnnotationHandler();
        handler.setFailOnEmptyAuthorizationConfig(true);
        runWithSubject(subject -> assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> handler.assertAuthorized(emptyRoles())));
    }

    @Test
    public void permissionsWarnByDefault() throws Throwable {
        PermissionAnnotationHandler handler = new PermissionAnnotationHandler();
        runWithSubject(subject -> assertThatExceptionOfType(UnauthenticatedException.class)
                .isThrownBy(() -> handler.assertAuthorized(emptyPermissions())));
    }

    @Test
    public void permissionsThrowWhenStrict() throws Throwable {
        PermissionAnnotationHandler handler = new PermissionAnnotationHandler();
        handler.setFailOnEmptyAuthorizationConfig(true);
        runWithSubject(subject -> assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> handler.assertAuthorized(emptyPermissions())));
    }
}

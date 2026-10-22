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
package org.apache.shiro.web.filter.authz;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.createNiceMock;

/**
 * Tests that the {@code perms} and {@code roles} filters warn and allow by default, and deny when so configured,
 * if no permissions or roles are configured.
 */
class EmptyAuthorizationConfigFilterTest {
    private final ServletRequest request = createNiceMock(ServletRequest.class);
    private final ServletResponse response = createNiceMock(ServletResponse.class);

    @BeforeEach
    void bindSubject() {
        Subject subject = createNiceMock(Subject.class);
        ThreadContext.bind(subject);
    }

    @AfterEach
    void unbind() {
        ThreadContext.remove();
    }

    @Test
    void permsAllowsEmptyConfigByDefault() throws Exception {
        PermissionsAuthorizationFilter filter = new PermissionsAuthorizationFilter();
        filter.processPathConfig("/admin/**", null);
        assertThat(filter.isAccessAllowed(request, response, null)).isTrue();
        assertThat(filter.isAccessAllowed(request, response, new String[0])).isTrue();
    }

    @Test
    void permsDeniesEmptyConfigWhenStrict() throws Exception {
        PermissionsAuthorizationFilter filter = new PermissionsAuthorizationFilter();
        filter.setFailOnEmptyAuthorizationConfig(true);
        filter.processPathConfig("/admin/**", "");
        assertThat(filter.isAccessAllowed(request, response, null)).isFalse();
        assertThat(filter.isAccessAllowed(request, response, new String[0])).isFalse();
    }

    @Test
    void rolesAllowsEmptyConfigByDefault() throws Exception {
        RolesAuthorizationFilter filter = new RolesAuthorizationFilter();
        filter.processPathConfig("/admin/**", null);
        assertThat(filter.isAccessAllowed(request, response, null)).isTrue();
        assertThat(filter.isAccessAllowed(request, response, new String[0])).isTrue();
    }

    @Test
    void rolesDeniesEmptyConfigWhenStrict() throws Exception {
        RolesAuthorizationFilter filter = new RolesAuthorizationFilter();
        filter.setFailOnEmptyAuthorizationConfig(true);
        filter.processPathConfig("/admin/**", "");
        assertThat(filter.isAccessAllowed(request, response, null)).isFalse();
        assertThat(filter.isAccessAllowed(request, response, new String[0])).isFalse();
    }
}

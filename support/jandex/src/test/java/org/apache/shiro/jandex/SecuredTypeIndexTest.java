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
package org.apache.shiro.jandex;

import org.apache.shiro.aop.fixtures.MethodSecuredInterface;
import org.apache.shiro.aop.fixtures.SecuredBase;
import org.apache.shiro.aop.fixtures.SecuredInterface;
import org.apache.shiro.authz.aop.AuthorizationAnnotations;
import org.apache.shiro.jandex.SecuredTypeIndex.SkipReason;
import org.apache.shiro.jandex.fixtures.AbstractImpl;
import org.apache.shiro.jandex.fixtures.ComposedImpl;
import org.apache.shiro.jandex.fixtures.ComposedInterface;
import org.apache.shiro.jandex.fixtures.DirectlyAnnotatedImpl;
import org.apache.shiro.jandex.fixtures.EjbImpl;
import org.apache.shiro.jandex.fixtures.FinalImpl;
import org.apache.shiro.jandex.fixtures.MethodScopedImpl;
import org.apache.shiro.jandex.fixtures.MyStereotype;
import org.apache.shiro.jandex.fixtures.PlainImpl;
import org.apache.shiro.jandex.fixtures.ScopedImpl;
import org.apache.shiro.jandex.fixtures.ScopedSubclass;
import org.apache.shiro.jandex.fixtures.ScopedSubclassOfImpl;
import org.apache.shiro.jandex.fixtures.StereotypedImpl;
import org.apache.shiro.jandex.fixtures.UnrelatedBean;
import org.apache.shiro.jandex.fixtures.VetoedImpl;
import org.apache.shiro.jandex.fixtures.vetoed.PackageVetoedImpl;
import org.jboss.jandex.Index;
import org.jboss.jandex.Indexer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecuredTypeIndexTest {

    /**
     * Only the module's own fixtures are indexed; the core fixtures (the secured interfaces and base class and the
     * composed annotation) play the role of a library shipped without a Jandex index.
     */
    private static Index applicationIndex() throws IOException {
        Indexer indexer = new Indexer();
        for (Class<?> type : List.of(ScopedImpl.class, ScopedSubclassOfImpl.class, MethodScopedImpl.class,
                ScopedSubclass.class, PlainImpl.class, FinalImpl.class, VetoedImpl.class, EjbImpl.class,
                AbstractImpl.class, DirectlyAnnotatedImpl.class, MyStereotype.class, StereotypedImpl.class,
                ComposedInterface.class, ComposedImpl.class, UnrelatedBean.class, PackageVetoedImpl.class)) {
            index(indexer, type.getName());
        }
        index(indexer, PackageVetoedImpl.class.getPackageName() + ".package-info");
        return indexer.complete();
    }

    private static void index(Indexer indexer, String className) throws IOException {
        try (InputStream in = SecuredTypeIndexTest.class.getClassLoader()
                .getResourceAsStream(className.replace('.', '/') + ".class")) {
            indexer.index(in);
        }
    }

    private static SecuredTypeIndex load() throws IOException {
        return SecuredTypeIndex.of(SecuredTypeIndexTest.class.getClassLoader(), AuthorizationAnnotations.allTypes(),
                List.of(applicationIndex()));
    }

    @Test
    void directlySecuredIncludesLibraryTypesAndComposedAnnotations() throws IOException {
        SecuredTypeIndex index = load();
        assertThat(index.isIndexed()).isTrue();
        assertThat(index.directlySecured()).containsExactlyInAnyOrder(SecuredInterface.class.getName(),
                MethodSecuredInterface.class.getName(), SecuredBase.class.getName(), ComposedInterface.class.getName(),
                DirectlyAnnotatedImpl.class.getName());
    }

    @Test
    void candidatesAreIndirectlySecuredBeans() throws IOException {
        SecuredTypeIndex index = load();
        assertThat(index.candidates()).containsExactlyInAnyOrder(ScopedImpl.class.getName(),
                ScopedSubclassOfImpl.class.getName(), MethodScopedImpl.class.getName(), ScopedSubclass.class.getName(),
                StereotypedImpl.class.getName(), ComposedImpl.class.getName());
        assertThat(index.indirectlySecured()).containsAll(index.candidates()).containsAll(index.skipped().keySet())
                .doesNotContain(DirectlyAnnotatedImpl.class.getName(), UnrelatedBean.class.getName());
    }

    @Test
    void skippedWithReason() throws IOException {
        assertThat(load().skipped()).containsExactlyInAnyOrderEntriesOf(Map.of(
                PlainImpl.class.getName(), SkipReason.NOT_A_BEAN,
                FinalImpl.class.getName(), SkipReason.FINAL,
                VetoedImpl.class.getName(), SkipReason.VETOED,
                PackageVetoedImpl.class.getName(), SkipReason.VETOED,
                EjbImpl.class.getName(), SkipReason.EJB,
                AbstractImpl.class.getName(), SkipReason.NOT_INSTANTIABLE));
    }

    @Test
    void noIndexMeansNothingDiscovered() {
        SecuredTypeIndex index = SecuredTypeIndex.of(getClass().getClassLoader(), AuthorizationAnnotations.allTypes(),
                List.of());
        assertThat(index.isIndexed()).isFalse();
        assertThat(index.directlySecured()).isEmpty();
        assertThat(index.candidates()).isEmpty();
    }

    @Test
    void loadFromClassPathWithoutIndexResources() {
        SecuredTypeIndex index = SecuredTypeIndex.load(getClass().getClassLoader(), AuthorizationAnnotations.shiroTypes());
        assertThat(index.isIndexed()).isFalse();
    }
}

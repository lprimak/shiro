/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.cdi;

import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.literal.NamedLiteral;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.cdi.fixtures.Counter;
import org.apache.shiro.cdi.fixtures.DirectlySecuredBean;
import org.apache.shiro.cdi.fixtures.InterfaceSecuredBean;
import org.apache.shiro.cdi.fixtures.Jsr250Bean;
import org.apache.shiro.cdi.fixtures.MethodInterfaceSecuredBean;
import org.apache.shiro.cdi.fixtures.Ping;
import org.apache.shiro.cdi.fixtures.SuperclassSecuredBean;
import org.apache.shiro.cdi.fixtures.UnsecuredBean;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.ExecutionException;
import org.apache.shiro.subject.Subject;
import org.jboss.weld.environment.se.Weld;
import org.jboss.weld.environment.se.WeldContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Boots Weld SE against the module's test classes (indexed by the Jandex Maven plugin) and proves that
 * beans secured only through interfaces or superclasses are intercepted exactly like directly annotated ones.
 */
class ShiroSecurityExtensionWeldTest {
    private static WeldContainer container;
    private static DefaultSecurityManager securityManager;

    @BeforeAll
    static void start() {
        container = new Weld().disableDiscovery()
                .addExtension(new ShiroSecurityExtension())
                .addBeanClass(ShiroSecurityInterceptor.class)
                .addPackages(Counter.class)
                .initialize();
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.addAccount("alice", "secret", "user");
        realm.addAccount("root", "secret", "admin", "user");
        securityManager = new DefaultSecurityManager(realm);
    }

    @AfterAll
    static void stop() {
        container.close();
        securityManager.destroy();
    }

    @Test
    void interfaceTypeLevelAnnotationIsEnforced() {
        InterfaceSecuredBean bean = container.select(InterfaceSecuredBean.class).get();
        assertThatThrownBy(() -> asGuest(bean::adminOnly)).isInstanceOf(AuthorizationException.class);
        assertThatThrownBy(() -> as("alice", bean::adminOnly)).isInstanceOf(AuthorizationException.class);
        assertThat(as("root", bean::adminOnly)).isEqualTo("admin:true");
    }

    @Test
    void replacedBeanIsRegisteredExactlyOnce() {
        Instance<InterfaceSecuredBean> beans = container.select(InterfaceSecuredBean.class);
        assertThat(beans.isResolvable()).isTrue();
        Instance<String> produced = container.select(String.class, NamedLiteral.of("fromInterfaceSecuredBean"));
        assertThat(produced.isResolvable()).as("producer of the replaced bean registered once").isTrue();
        // the producer and the observer are business methods of the secured bean, so they are intercepted too
        assertThatThrownBy(() -> asGuest(produced::get)).isInstanceOf(AuthorizationException.class);
        assertThat(as("root", produced::get)).isEqualTo("produced");
        Counter counter = container.select(Counter.class).get();
        as("root", () -> {
            container.getBeanManager().getEvent().fire(new Ping());
            return null;
        });
        assertThat(counter.getEvents()).as("observer of the replaced bean registered once").isEqualTo(1);
    }

    @Test
    void interfaceMethodLevelAnnotationIsEnforced() {
        MethodInterfaceSecuredBean bean = container.select(MethodInterfaceSecuredBean.class).get();
        assertThat(bean.getClass()).as("intercepted subclass").isNotEqualTo(MethodInterfaceSecuredBean.class);
        assertThatThrownBy(() -> asGuest(bean::read)).isInstanceOf(AuthorizationException.class);
        assertThat(asGuest(bean::open)).isEqualTo("open");
    }

    @Test
    void superclassTypeLevelAnnotationIsEnforced() {
        SuperclassSecuredBean bean = container.select(SuperclassSecuredBean.class).get();
        assertThatThrownBy(() -> asGuest(bean::ownOperation)).isInstanceOf(UnauthenticatedException.class);
        assertThatThrownBy(() -> asGuest(bean::baseOperation)).isInstanceOf(UnauthenticatedException.class);
        assertThat(as("alice", bean::ownOperation)).isEqualTo("own");
    }

    @Test
    void directAndJsr250AnnotationsStillWork() {
        DirectlySecuredBean direct = container.select(DirectlySecuredBean.class).get();
        assertThatThrownBy(() -> asGuest(direct::authenticated)).isInstanceOf(UnauthenticatedException.class);
        assertThat(asGuest(direct::open)).isEqualTo("open");

        Jsr250Bean jsr250 = container.select(Jsr250Bean.class).get();
        assertThatThrownBy(() -> as("alice", jsr250::admin)).isInstanceOf(AuthorizationException.class);
        assertThat(as("root", jsr250::admin)).isEqualTo("admin");
        assertThatThrownBy(() -> as("root", jsr250::denied)).isInstanceOf(AuthorizationException.class);
        assertThat(asGuest(jsr250::permitted)).isEqualTo("permitted");
        assertThat(asGuest(jsr250::open)).isEqualTo("open");
    }

    @Test
    void unsecuredBeanIsNotIntercepted() {
        UnsecuredBean bean = container.select(UnsecuredBean.class).get();
        assertThat(bean.getClass()).isEqualTo(UnsecuredBean.class);
        assertThat(asGuest(bean::open)).isEqualTo("open");
    }

    private static <T> T asGuest(Supplier<T> action) {
        return execute(new Subject.Builder(securityManager).buildSubject(), action);
    }

    private static <T> T as(String user, Supplier<T> action) {
        Subject subject = new Subject.Builder(securityManager).buildSubject();
        subject.login(new UsernamePasswordToken(user, "secret"));
        try {
            return execute(subject, action);
        } finally {
            subject.logout();
        }
    }

    private static <T> T execute(Subject subject, Supplier<T> action) {
        try {
            return subject.execute(action::get);
        } catch (ExecutionException e) {
            throw (RuntimeException) e.getCause();
        }
    }
}

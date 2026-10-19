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


import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.spi.AfterTypeDiscovery;
import jakarta.enterprise.inject.spi.Annotated;
import jakarta.enterprise.inject.spi.AnnotatedMember;
import jakarta.enterprise.inject.spi.AnnotatedType;
import jakarta.enterprise.inject.spi.BeforeBeanDiscovery;
import jakarta.enterprise.inject.spi.Extension;
import jakarta.enterprise.inject.spi.ProcessAnnotatedType;
import jakarta.enterprise.inject.spi.ProcessBeanAttributes;
import jakarta.enterprise.inject.spi.ProcessObserverMethod;
import jakarta.enterprise.inject.spi.WithAnnotations;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.authz.aop.AuthorizationAnnotations;
import org.apache.shiro.jandex.SecuredTypeIndex;
import org.apache.shiro.jandex.SecuredTypeIndex.SkipReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.annotation.Annotation;
import java.util.Set;

/**
 * Automatically apply Shiro security to all appropriate beans.
 * <p>
 * Types that carry an authorization annotation themselves (on the type or a method, directly or through a
 * composed annotation) are found by the container via {@link WithAnnotations}. Types that are secured only
 * because they implement a secured interface or extend a secured class are found through the Jandex index
 * ({@code META-INF/jandex.idx}, see {@link SecuredTypeIndex}): for each such bean class a synthetic
 * {@link AnnotatedType} carrying the interceptor binding is registered and the originally discovered bean,
 * its producers and its observer methods are vetoed, so exactly one, intercepted, bean remains.
 */
public class ShiroSecurityExtension implements Extension {
    /**
     * Carrier of the interceptor binding instance.
     */
    @ShiroSecureAnnotation
    public static class ShiroSecureAnnotated {
    }

    @ShiroSyntheticType
    private static final class ShiroSyntheticAnnotated {
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(ShiroSecurityExtension.class);
    private static final String SYNTHETIC_ID_PREFIX = "shiro-secured:";
    private static final Annotation SHIRO_SECURE = ShiroSecureAnnotated.class.getDeclaredAnnotations()[0];
    private static final Annotation SYNTHETIC = ShiroSyntheticAnnotated.class.getDeclaredAnnotations()[0];

    private Set<String> candidates = Set.of();

    public <T> void addSecurity(@Observes @WithAnnotations({
            RequiresAuthentication.class, RequiresGuest.class, RequiresPermissions.class,
            RequiresRoles.class, RequiresUser.class, RolesAllowed.class,
            PermitAll.class, DenyAll.class}) ProcessAnnotatedType<T> pat) {
        pat.setAnnotatedType(new AnnotatedTypeWrapper<>(pat.getAnnotatedType(), SHIRO_SECURE));
    }

    void discoverIndirectlySecured(@Observes BeforeBeanDiscovery event) {
        SecuredTypeIndex index = SecuredTypeIndex.load(classLoader(), AuthorizationAnnotations.allTypes());
        candidates = index.candidates();
        index.skipped().forEach((name, reason) -> {
            if (reason == SkipReason.FINAL || reason == SkipReason.EJB) {
                LOGGER.warn("{} is secured through a supertype but cannot be intercepted ({}); "
                        + "annotate the class directly", name, reason);
            }
        });
        LOGGER.debug("Indirectly secured bean classes: {}", candidates);
    }

    void replaceIndirectlySecured(@Observes AfterTypeDiscovery event) {
        for (String name : candidates) {
            try {
                Class<?> type = Class.forName(name, false, classLoader());
                event.addAnnotatedType(type, SYNTHETIC_ID_PREFIX + name).add(SHIRO_SECURE).add(SYNTHETIC);
            } catch (ClassNotFoundException | LinkageError e) {
                LOGGER.warn("Unable to load indirectly secured class {}", name, e);
            }
        }
    }

    void vetoReplacedBeans(@Observes ProcessBeanAttributes<?> event) {
        if (isReplacedOriginal(event.getAnnotated())) {
            event.veto();
        }
    }

    void vetoReplacedObservers(@Observes ProcessObserverMethod<?, ?> event) {
        if (isReplacedOriginal(event.getAnnotatedMethod())) {
            event.veto();
        }
    }

    private boolean isReplacedOriginal(Annotated annotated) {
        AnnotatedType<?> type = null;
        if (annotated instanceof AnnotatedType) {
            type = (AnnotatedType<?>) annotated;
        } else if (annotated instanceof AnnotatedMember) {
            type = ((AnnotatedMember<?>) annotated).getDeclaringType();
        }
        return type != null && candidates.contains(type.getJavaClass().getName())
                && !type.isAnnotationPresent(ShiroSyntheticType.class);
    }

    private ClassLoader classLoader() {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        return loader != null ? loader : ShiroSecurityExtension.class.getClassLoader();
    }
}

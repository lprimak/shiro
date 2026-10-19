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

import org.apache.shiro.aop.AnnotationHierarchy;
import org.apache.shiro.aop.AnnotationResolver;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.lang.util.ClassUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The single registry of authorization annotations Shiro understands, their handlers and method interceptors,
 * together with the hierarchy-aware lookups every integration (Spring, Guice, CDI, JAX-RS, AspectJ) uses
 * to decide whether a class or method is secured.
 * <p>
 * The five Shiro annotations are always available. The JSR-250 annotations ({@code @RolesAllowed},
 * {@code @PermitAll}, {@code @DenyAll}) are registered only when {@code jakarta.annotation} is on the class path.
 *
 * @since 2.1
 */
public final class AuthorizationAnnotations {
    private static final String JSR250_PROBE = "jakarta.annotation.security.RolesAllowed";

    private static final Map<Class<? extends Annotation>, Function<AnnotationResolver, AuthorizingAnnotationMethodInterceptor>>
            SHIRO = shiroRegistry();
    private static final Map<Class<? extends Annotation>, Function<AnnotationResolver, AuthorizingAnnotationMethodInterceptor>>
            JSR250 = jsr250Registry();
    private static final Map<Class<? extends Annotation>, Function<AnnotationResolver, AuthorizingAnnotationMethodInterceptor>>
            ALL = merge(SHIRO, JSR250);

    private AuthorizationAnnotations() {
    }

    /**
     * @return the five Shiro authorization annotations, in enforcement order
     */
    public static Set<Class<? extends Annotation>> shiroTypes() {
        return SHIRO.keySet();
    }

    /**
     * @return the JSR-250 annotations, or an empty set when {@code jakarta.annotation} is not available
     */
    public static Set<Class<? extends Annotation>> jsr250Types() {
        return JSR250.keySet();
    }

    /**
     * @return {@link #shiroTypes()} followed by {@link #jsr250Types()}
     */
    public static Set<Class<? extends Annotation>> allTypes() {
        return ALL.keySet();
    }

    /**
     * Creates the handler enforcing the given annotation type.
     *
     * @param annotationType one of {@link #allTypes()}
     * @return a new handler
     * @throws IllegalArgumentException for an unknown annotation type
     */
    public static AuthorizingAnnotationHandler createHandler(Class<? extends Annotation> annotationType) {
        return (AuthorizingAnnotationHandler) createMethodInterceptor(annotationType, null).getHandler();
    }

    /**
     * Creates the method interceptor enforcing the given annotation type.
     *
     * @param annotationType one of {@link #allTypes()}
     * @param resolver       the resolver to use, or {@code null} for the default
     * @return a new method interceptor
     * @throws IllegalArgumentException for an unknown annotation type
     */
    public static AuthorizingAnnotationMethodInterceptor createMethodInterceptor(Class<? extends Annotation> annotationType,
                                                                                 AnnotationResolver resolver) {
        var factory = ALL.get(annotationType);
        if (factory == null) {
            throw new IllegalArgumentException("Cannot create a handler for the unknown annotation " + annotationType);
        }
        return factory.apply(resolver);
    }

    /**
     * Creates one method interceptor per annotation type, all sharing the given resolver.
     *
     * @param resolver        the resolver to use, or {@code null} for the default
     * @param annotationTypes the annotation types to enforce
     * @return new interceptors, in the order of the given types
     */
    public static List<AuthorizingAnnotationMethodInterceptor> createMethodInterceptors(
            AnnotationResolver resolver, Collection<Class<? extends Annotation>> annotationTypes) {
        return annotationTypes.stream().map(type -> createMethodInterceptor(type, resolver)).collect(Collectors.toList());
    }

    /**
     * Returns whether any of the given annotations is present on the class, its supertypes, or any of their methods.
     *
     * @param targetClass     the class to inspect
     * @param annotationTypes the annotation types of interest
     * @return {@code true} if the class should be intercepted at all
     */
    public static boolean isSecured(Class<?> targetClass, Collection<Class<? extends Annotation>> annotationTypes) {
        return annotationTypes.stream().anyMatch(type -> AnnotationHierarchy.isPresent(targetClass, type));
    }

    /**
     * Returns whether the invocation of the given method on the given target class is subject to any of the
     * given annotations, at method or type level, anywhere in the hierarchy.
     *
     * @param method          the invoked method
     * @param targetClass     the class the method is invoked on, or {@code null} for the method's declaring class
     * @param annotationTypes the annotation types of interest
     * @return {@code true} if the method invocation must be authorized
     */
    public static boolean isSecured(Method method, Class<?> targetClass,
                                    Collection<Class<? extends Annotation>> annotationTypes) {
        return annotationTypes.stream().anyMatch(type -> findAnnotation(method, targetClass, type) != null);
    }

    /**
     * Finds the annotation governing an invocation of the method on the target class.
     *
     * @param method         the invoked method
     * @param targetClass    the class the method is invoked on, or {@code null} for the method's declaring class
     * @param annotationType the annotation type to look for
     * @return the annotation, or {@code null}
     * @see AnnotationHierarchy#findAnnotation(Method, Class, Class)
     */
    public static Annotation findAnnotation(Method method, Class<?> targetClass, Class<? extends Annotation> annotationType) {
        return AnnotationHierarchy.findAnnotation(method,
                targetClass != null ? targetClass : method.getDeclaringClass(), annotationType);
    }

    private static Map<Class<? extends Annotation>, Function<AnnotationResolver, AuthorizingAnnotationMethodInterceptor>>
    shiroRegistry() {
        var registry = new LinkedHashMap<Class<? extends Annotation>,
                Function<AnnotationResolver, AuthorizingAnnotationMethodInterceptor>>();
        registry.put(RequiresRoles.class, RoleAnnotationMethodInterceptor::new);
        registry.put(RequiresPermissions.class, PermissionAnnotationMethodInterceptor::new);
        registry.put(RequiresAuthentication.class, AuthenticatedAnnotationMethodInterceptor::new);
        registry.put(RequiresUser.class, UserAnnotationMethodInterceptor::new);
        registry.put(RequiresGuest.class, GuestAnnotationMethodInterceptor::new);
        return Collections.unmodifiableMap(registry);
    }

    private static Map<Class<? extends Annotation>, Function<AnnotationResolver, AuthorizingAnnotationMethodInterceptor>>
    jsr250Registry() {
        if (!ClassUtils.isAvailable(JSR250_PROBE)) {
            return Map.of();
        }
        var registry = new LinkedHashMap<Class<? extends Annotation>,
                Function<AnnotationResolver, AuthorizingAnnotationMethodInterceptor>>();
        registry.put(jakarta.annotation.security.RolesAllowed.class, RolesAllowedAnnotationMethodInterceptor::new);
        registry.put(jakarta.annotation.security.PermitAll.class, PermitAllAnnotationMethodInterceptor::new);
        registry.put(jakarta.annotation.security.DenyAll.class, DenyAllAnnotationMethodInterceptor::new);
        return Collections.unmodifiableMap(registry);
    }

    private static <K, V> Map<K, V> merge(Map<K, V> first, Map<K, V> second) {
        var merged = new LinkedHashMap<K, V>(first);
        merged.putAll(second);
        return Collections.unmodifiableMap(merged);
    }
}

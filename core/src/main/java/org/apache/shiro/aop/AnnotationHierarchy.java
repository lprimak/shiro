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
package org.apache.shiro.aop;

import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.ClassUtils.Interfaces;
import org.apache.commons.lang3.reflect.MethodUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.stream.StreamSupport;

/**
 * Framework-independent, cached discovery of annotations across a type hierarchy.
 * <p>
 * The lookup rules are the same for every Shiro integration (Spring, Guice, CDI, JAX-RS, AspectJ).
 * The closest declaration wins: the invoked method itself is inspected first, then every type of the target's
 * hierarchy (the target class, its interfaces, its superclass and so on, see {@link #hierarchy(Class)}),
 * most specific first. At each type the method overridden or implemented there is inspected before the type
 * itself, so a method-level annotation overrides a type-level annotation of the same type declared at the same
 * level or further up, and a subclass can restrict inherited methods with a type-level annotation.
 * At every step the annotation may be present directly or as a meta-annotation (composed annotation).
 * <p>
 * Results are cached per target class using {@link ClassValue}, so cache entries are reclaimed together with
 * the class loader that defined the target class.
 *
 * @since 2.1
 */
public final class AnnotationHierarchy {
    private static final String JAVA_LANG_ANNOTATION = "java.lang.annotation.";

    private static final ClassValue<Cache> CACHE = new ClassValue<>() {
        @Override
        protected Cache computeValue(Class<?> type) {
            return new Cache(hierarchyOf(type));
        }
    };

    /**
     * Cache key; a {@code null} method means a type-level lookup.
     */
    private record Key(Method method, Class<? extends Annotation> annotationType) {
    }

    /**
     * Per target class cache.
     */
    private record Cache(List<Class<?>> hierarchy, Map<Key, Optional<Annotation>> found,
                         Map<Class<? extends Annotation>, Boolean> present) {
        Cache(List<Class<?>> hierarchy) {
            this(hierarchy, new ConcurrentHashMap<>(), new ConcurrentHashMap<>());
        }
    }

    private AnnotationHierarchy() {
    }

    /**
     * Returns the type hierarchy of the given class, most specific first: the class itself, its interfaces,
     * then its superclass with that class's interfaces and so on, without duplicates and without
     * {@link Object}.
     *
     * @param type the class to inspect
     * @return an unmodifiable list, never empty
     */
    public static List<Class<?>> hierarchy(Class<?> type) {
        return CACHE.get(type).hierarchy();
    }

    /**
     * Determines the class whose hierarchy should be searched for a method invocation: the runtime class
     * of the invocation target, or the method's declaring class for static methods.
     *
     * @param target the object the method is invoked on, may be {@code null}
     * @param method the invoked method
     * @return the class to search
     */
    public static Class<?> targetClass(Object target, Method method) {
        return target != null ? target.getClass() : method.getDeclaringClass();
    }

    /**
     * Finds the annotation governing an invocation of the method on the target class, closest declaration first
     * (see the class documentation).
     *
     * @param method         the invoked method
     * @param targetClass    the class to search, see {@link #targetClass(Object, Method)}
     * @param annotationType the annotation to look for
     * @param <A>            the annotation type
     * @return the annotation, or {@code null} if not found anywhere in the hierarchy
     */
    public static <A extends Annotation> A findAnnotation(Method method, Class<?> targetClass, Class<A> annotationType) {
        Class<?> searchRoot = targetClass != null ? targetClass : method.getDeclaringClass();
        return cached(searchRoot, new Key(method, annotationType), () -> searchInvocation(method, searchRoot, annotationType));
    }

    /**
     * Finds a type-level annotation on the target class, its superclasses or its interfaces.
     *
     * @param targetClass    the class to search
     * @param annotationType the annotation to look for
     * @param <A>            the annotation type
     * @return the annotation, or {@code null} if not found
     */
    public static <A extends Annotation> A findTypeAnnotation(Class<?> targetClass, Class<A> annotationType) {
        return cached(targetClass, new Key(null, annotationType), () -> searchTypes(hierarchy(targetClass), annotationType));
    }

    /**
     * Returns whether the annotation is present anywhere in the hierarchy of the target class,
     * either at type level or on any declared method. This is the "should this class be intercepted at all"
     * question that every integration asks when wiring interceptors.
     *
     * @param targetClass    the class to search
     * @param annotationType the annotation to look for
     * @return {@code true} if the class or any of its methods is (directly or indirectly) annotated
     */
    public static boolean isPresent(Class<?> targetClass, Class<? extends Annotation> annotationType) {
        return CACHE.get(targetClass).present().computeIfAbsent(annotationType, type -> hierarchy(targetClass).stream()
                .anyMatch(declaring -> findDeclared(declaring, type) != null || Arrays.stream(declaring.getDeclaredMethods())
                        .anyMatch(method -> !method.isBridge() && !method.isSynthetic() && findDeclared(method, type) != null)));
    }

    /**
     * Finds the annotation directly on the element or as a meta-annotation of any annotation present on it.
     *
     * @param element        the method or class to inspect
     * @param annotationType the annotation to look for
     * @param <A>            the annotation type
     * @return the annotation, or {@code null} if not found
     */
    public static <A extends Annotation> A findDeclared(AnnotatedElement element, Class<A> annotationType) {
        return findDeclared(element, annotationType, new HashSet<>());
    }

    @SuppressWarnings("unchecked")
    private static <A extends Annotation> A cached(Class<?> root, Key key, Supplier<A> search) {
        return (A) CACHE.get(root).found().computeIfAbsent(key, k -> Optional.ofNullable(search.get())).orElse(null);
    }

    private static <A extends Annotation> A searchInvocation(Method method, Class<?> targetClass, Class<A> annotationType) {
        A annotation = findDeclared(method, annotationType);
        if (annotation != null) {
            return annotation;
        }
        Map<Class<?>, Method> overridden = overriddenMethods(method, targetClass);
        for (Class<?> type : hierarchy(targetClass)) {
            Method declared = overridden.get(type);
            annotation = declared != null ? findDeclared(declared, annotationType) : null;
            annotation = annotation != null ? annotation : findDeclared(type, annotationType);
            if (annotation != null) {
                return annotation;
            }
        }
        return null;
    }

    /**
     * The method as declared in each type it overrides or implements, found by the most specific
     * declaration visible from the target class (generic overrides and bridge methods included).
     */
    private static Map<Class<?>, Method> overriddenMethods(Method invoked, Class<?> targetClass) {
        Method mostSpecific = Optional.ofNullable(
                MethodUtils.getMatchingMethod(targetClass, invoked.getName(), invoked.getParameterTypes())).orElse(invoked);
        Map<Class<?>, Method> result = new HashMap<>();
        MethodUtils.getOverrideHierarchy(mostSpecific, Interfaces.INCLUDE)
                .forEach(method -> result.putIfAbsent(method.getDeclaringClass(), method));
        result.putIfAbsent(invoked.getDeclaringClass(), invoked);
        return result;
    }

    private static <A extends Annotation> A searchTypes(List<Class<?>> hierarchy, Class<A> annotationType) {
        return hierarchy.stream().map(type -> findDeclared(type, annotationType)).filter(Objects::nonNull)
                .findFirst().orElse(null);
    }

    private static <A extends Annotation> A findDeclared(AnnotatedElement element, Class<A> annotationType,
                                                         Set<Class<? extends Annotation>> visited) {
        A annotation = element.getDeclaredAnnotation(annotationType);
        if (annotation != null) {
            return annotation;
        }
        return Arrays.stream(element.getDeclaredAnnotations()).map(Annotation::annotationType)
                .filter(metaType -> !metaType.getName().startsWith(JAVA_LANG_ANNOTATION) && visited.add(metaType))
                .map(metaType -> findDeclared(metaType, annotationType, visited))
                .filter(Objects::nonNull).findFirst().orElse(null);
    }

    private static List<Class<?>> hierarchyOf(Class<?> type) {
        List<Class<?>> result = StreamSupport.stream(ClassUtils.hierarchy(type, Interfaces.INCLUDE).spliterator(), false)
                .filter(candidate -> candidate != Object.class).toList();
        return result.isEmpty() ? List.of(type) : result;
    }
}

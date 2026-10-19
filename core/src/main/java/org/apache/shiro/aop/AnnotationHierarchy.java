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

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Framework-independent, cached discovery of annotations across a type hierarchy.
 * <p>
 * The lookup rules are the same for every Shiro integration (Spring, Guice, CDI, JAX-RS, AspectJ).
 * The closest declaration wins: the invoked method itself is inspected first, then every type of the target's
 * linearized hierarchy (the target class, its superclasses, then its interfaces, see {@link #hierarchy(Class)}),
 * most specific first. At each type the method with the same signature is inspected before the type itself,
 * so a method-level annotation overrides a type-level annotation of the same type declared at the same level or
 * further up, and a subclass can restrict inherited methods with a type-level annotation.
 * At every step the annotation may be present directly or as a meta-annotation (composed annotation).
 * <p>
 * Results are cached per target class using {@link ClassValue}, so cache entries are reclaimed together with
 * the class loader that defined the target class.
 *
 * @since 2.1
 */
public final class AnnotationHierarchy {
    private static final String JAVA_LANG_ANNOTATION = "java.lang.annotation.";

    private static final ClassValue<TypeCache> CACHE = new ClassValue<>() {
        @Override
        protected TypeCache computeValue(Class<?> type) {
            return new TypeCache(linearize(type));
        }
    };

    /**
     * Per target class cache holder.
     */
    private static final class TypeCache {
        private final List<Class<?>> hierarchy;
        private final Map<Class<? extends Annotation>, Optional<Annotation>> typeAnnotations = new ConcurrentHashMap<>();
        private final Map<Method, Map<Class<? extends Annotation>, Optional<Annotation>>> methodAnnotations
                = new ConcurrentHashMap<>();
        private final Map<Class<? extends Annotation>, Boolean> present = new ConcurrentHashMap<>();

        TypeCache(List<Class<?>> hierarchy) {
            this.hierarchy = hierarchy;
        }
    }

    private AnnotationHierarchy() {
    }

    /**
     * Returns the linearized type hierarchy of the given class: the class itself, its superclasses
     * (excluding {@link Object}) and then all its interfaces, breadth first, without duplicates.
     *
     * @param type the class to linearize
     * @return an unmodifiable list, never empty
     */
    public static List<Class<?>> hierarchy(Class<?> type) {
        return CACHE.get(type).hierarchy;
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
    @SuppressWarnings("unchecked")
    public static <A extends Annotation> A findAnnotation(Method method, Class<?> targetClass, Class<A> annotationType) {
        Class<?> searchRoot = targetClass != null ? targetClass : method.getDeclaringClass();
        Map<Class<? extends Annotation>, Optional<Annotation>> perMethod = CACHE.get(searchRoot).methodAnnotations
                .computeIfAbsent(method, m -> new ConcurrentHashMap<>());
        return (A) perMethod.computeIfAbsent(annotationType,
                type -> Optional.ofNullable(search(method, searchRoot, type))).orElse(null);
    }

    /**
     * Finds a type-level annotation on the target class, its superclasses or its interfaces.
     *
     * @param targetClass    the class to search
     * @param annotationType the annotation to look for
     * @param <A>            the annotation type
     * @return the annotation, or {@code null} if not found
     */
    @SuppressWarnings("unchecked")
    public static <A extends Annotation> A findTypeAnnotation(Class<?> targetClass, Class<A> annotationType) {
        TypeCache cache = CACHE.get(targetClass);
        return (A) cache.typeAnnotations.computeIfAbsent(annotationType,
                type -> Optional.ofNullable(searchTypes(cache.hierarchy, type))).orElse(null);
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
        TypeCache cache = CACHE.get(targetClass);
        return cache.present.computeIfAbsent(annotationType, type -> searchTypes(cache.hierarchy, type) != null
                || cache.hierarchy.stream().anyMatch(declaring -> anyMethodAnnotated(declaring, type)));
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

    private static <A extends Annotation> A search(Method method, Class<?> targetClass, Class<A> annotationType) {
        A annotation = findDeclared(method, annotationType);
        if (annotation != null) {
            return annotation;
        }
        for (Class<?> declaring : searchOrder(method, targetClass)) {
            annotation = findOnDeclaredMethods(declaring, method, annotationType);
            if (annotation == null) {
                annotation = findDeclared(declaring, annotationType);
            }
            if (annotation != null) {
                return annotation;
            }
        }
        return null;
    }

    private static List<Class<?>> searchOrder(Method method, Class<?> targetClass) {
        List<Class<?>> types = hierarchy(targetClass);
        if (method.getDeclaringClass().isAssignableFrom(targetClass)) {
            return types;
        }
        // the invoked method belongs to an unrelated type (e.g. a decorator); search both hierarchies
        List<Class<?>> combined = new ArrayList<>(types);
        hierarchy(method.getDeclaringClass()).stream().filter(t -> !combined.contains(t)).forEach(combined::add);
        return combined;
    }

    private static <A extends Annotation> A findOnDeclaredMethods(Class<?> declaring, Method method, Class<A> annotationType) {
        for (Method candidate : declaring.getDeclaredMethods()) {
            if (overrides(candidate, method)) {
                A annotation = findDeclared(candidate, annotationType);
                if (annotation != null) {
                    return annotation;
                }
            }
        }
        return null;
    }

    private static boolean overrides(Method candidate, Method method) {
        if (candidate.isBridge() || candidate.isSynthetic() || !candidate.getName().equals(method.getName())) {
            return false;
        }
        Class<?>[] expected = method.getParameterTypes();
        Class<?>[] actual = candidate.getParameterTypes();
        if (expected.length != actual.length) {
            return false;
        }
        for (int i = 0; i < expected.length; i++) {
            // allow generic overrides (erased parameter types differ but are related)
            if (!expected[i].isAssignableFrom(actual[i]) && !actual[i].isAssignableFrom(expected[i])) {
                return false;
            }
        }
        return true;
    }

    private static <A extends Annotation> A searchTypes(List<Class<?>> hierarchy, Class<A> annotationType) {
        for (Class<?> type : hierarchy) {
            A annotation = findDeclared(type, annotationType);
            if (annotation != null) {
                return annotation;
            }
        }
        return null;
    }

    private static boolean anyMethodAnnotated(Class<?> declaring, Class<? extends Annotation> annotationType) {
        for (Method method : declaring.getDeclaredMethods()) {
            if (!method.isBridge() && !method.isSynthetic() && findDeclared(method, annotationType) != null) {
                return true;
            }
        }
        return false;
    }

    private static <A extends Annotation> A findDeclared(AnnotatedElement element, Class<A> annotationType,
                                                         Set<Class<? extends Annotation>> visited) {
        A annotation = element.getDeclaredAnnotation(annotationType);
        if (annotation != null) {
            return annotation;
        }
        for (Annotation meta : element.getDeclaredAnnotations()) {
            Class<? extends Annotation> metaType = meta.annotationType();
            if (!metaType.getName().startsWith(JAVA_LANG_ANNOTATION) && visited.add(metaType)) {
                annotation = findDeclared(metaType, annotationType, visited);
                if (annotation != null) {
                    return annotation;
                }
            }
        }
        return null;
    }

    private static List<Class<?>> linearize(Class<?> type) {
        Set<Class<?>> result = new LinkedHashSet<>();
        Deque<Class<?>> interfaces = new ArrayDeque<>();
        for (Class<?> current = type; current != null && current != Object.class; current = current.getSuperclass()) {
            result.add(current);
            Collections.addAll(interfaces, current.getInterfaces());
        }
        while (!interfaces.isEmpty()) {
            Class<?> iface = interfaces.poll();
            if (result.add(iface)) {
                Collections.addAll(interfaces, iface.getInterfaces());
            }
        }
        if (result.isEmpty()) {
            result.add(type);
        }
        return List.copyOf(result);
    }
}

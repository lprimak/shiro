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

import lombok.NonNull;
import lombok.experimental.UtilityClass;
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
import java.util.stream.StreamSupport;

/**
 * Framework-independent, cached discovery of annotations across a type hierarchy.
 * <p>
 * The lookup rules are the same for every Shiro integration (Spring, Guice, CDI, JAX-RS, AspectJ).
 * The closest declaration wins.
 * The invoked method itself is inspected first.
 * Then every type of the target's hierarchy is inspected, most specific first: the target class,
 * its interfaces, its superclass and so on.
 * At each type, the method it overrides or implements is inspected before the type itself.
 * So a method-level annotation overrides a type-level annotation of the same type declared at the same level
 * or further up.
 * A subclass can also restrict inherited methods with a type-level annotation.
 * At every step the annotation may be present directly or as a meta-annotation (composed annotation).
 * <p>
 * Results are cached per class using {@link ClassValue}.
 * A type shared by many classes, such as a common interface or base class, is inspected only once.
 * Only classes defined by this class's loader, or by a loader that has it as an ancestor, are cached.
 * A cache entry in any other class could keep this class's loader from being reclaimed.
 * Those classes are searched on every call instead.
 *
 * @since 3.0.2
 */
@UtilityClass
@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
public final class AnnotationHierarchy {
    private static final String JAVA_LANG_ANNOTATION = "java.lang.annotation.";

    private static final ClassValue<Cache> CACHE = new ClassValue<>() {
        @Override
        protected Cache computeValue(@NonNull Class<?> type) {
            return new Cache(type);
        }
    };

    /**
     * Cache key.
     */
    private record Key(Method method, Class<? extends Annotation> annotationType) { }

    /**
     * Per target class cache.
     */
    private record Cache(List<Class<?>> hierarchy, Map<Key, Optional<Annotation>> found,
                         Map<Class<? extends Annotation>, Boolean> own) {
        Cache(Class<?> type) {
            this(StreamSupport.stream(ClassUtils.hierarchy(type, Interfaces.INCLUDE).spliterator(), false)
                    .filter(candidate -> candidate != Object.class).toList(),
                    new ConcurrentHashMap<>(), new ConcurrentHashMap<>());
        }
    }

    /**
     * Finds the annotation governing an invocation of the method on the target class, closest declaration first
     * (see the class documentation).
     *
     * @param method         the invoked method
     * @param targetClass    the runtime class of the invocation target, or {@code null} for the method's declaring
     *                       class (static methods)
     * @param annotationType the annotation to look for
     * @param <A>            the annotation type
     * @return the annotation, or {@code null} if not found anywhere in the hierarchy
     */
    @SuppressWarnings("unchecked")
    public static <A extends Annotation> A findAnnotation(Method method, Class<?> targetClass, Class<A> annotationType) {
        Class<?> searchRoot = targetClass != null ? targetClass : method.getDeclaringClass();
        Cache cache = cacheFor(searchRoot);
        return (A) cache.found().computeIfAbsent(new Key(method, annotationType), key -> Optional.ofNullable(
                searchInvocation(method, searchRoot, cache.hierarchy(), annotationType))).orElse(null);
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
        return cacheFor(targetClass).hierarchy().stream().anyMatch(declaring -> cacheFor(declaring).own()
                .computeIfAbsent(annotationType, type -> findDeclared(declaring, type) != null
                        || Arrays.stream(declaring.getDeclaredMethods()).anyMatch(method -> !method.isBridge()
                        && !method.isSynthetic() && findDeclared(method, type) != null)));
    }

    /**
     * Finds the annotation directly on the element or as a meta-annotation of any annotation present on it.
     *
     * @param element        the method or class to inspect
     * @param annotationType the annotation to look for
     * @param <A>            the annotation type
     * @return the annotation, or {@code null} if not found
     */
    static <A extends Annotation> A findDeclared(AnnotatedElement element, Class<A> annotationType) {
        return findDeclared(element, annotationType, new HashSet<>());
    }

    private static <A extends Annotation> A searchInvocation(Method method, Class<?> targetClass,
                                                             List<Class<?>> hierarchy, Class<A> annotationType) {
        A annotation = findDeclared(method, annotationType);
        if (annotation != null) {
            return annotation;
        }
        Map<Class<?>, Method> overridden = overriddenMethods(method, targetClass);
        for (Class<?> type : hierarchy) {
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
     * Maps each type to the method it declares for the invoked method's signature.
     * The search starts from the most specific declaration visible from the target class.
     * Generic overrides and bridge methods are included.
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

    /**
     * Returns the cache of a class whose cache entry cannot keep this class's loader alive.
     * Any other class gets a throwaway cache that is never stored in the {@link ClassValue}.
     */
    private static Cache cacheFor(Class<?> type) {
        ClassLoader own = AnnotationHierarchy.class.getClassLoader();
        for (ClassLoader loader = type.getClassLoader(); loader != null; loader = loader.getParent()) {
            if (loader == own) {
                return CACHE.get(type);
            }
        }
        return own == null ? CACHE.get(type) : new Cache(type);
    }
}

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

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.AnnotationTarget;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.CompositeIndex;
import org.jboss.jandex.DotName;
import org.jboss.jandex.IndexReader;
import org.jboss.jandex.IndexView;
import org.jboss.jandex.Indexer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Discovers, from Jandex indexes and without loading any class, which types are secured by Shiro's
 * authorization annotations: directly (the annotation is on the type or one of its methods, possibly as a
 * meta-annotation) or indirectly (the type extends a secured class or implements a secured interface).
 * <p>
 * Every {@code META-INF/jandex.idx} resource visible to the class loader is merged. Supertypes and annotation
 * types that indexed classes refer to but that are not indexed themselves (typically from libraries built
 * without the Jandex Maven plugin) are indexed on the fly from their {@code .class} resources, so an application
 * that ships an index can still implement a secured interface from a library that does not.
 * <p>
 * The answers of this index only ever <em>add</em> interception; a missing or stale index can only leave an
 * indirectly secured type uncovered, never bypass a directly annotated one.
 *
 * @since 2.1
 */
public final class SecuredTypeIndex {
    /**
     * Class path location of the indexes produced by the Jandex Maven plugin.
     */
    public static final String INDEX_RESOURCE = "META-INF/jandex.idx";

    /**
     * Why an indirectly secured type is not a {@link #candidates() candidate} for interception.
     */
    public enum SkipReason {
        /**
         * Interface, annotation, enum or abstract class: never instantiated by the container.
         */
        NOT_INSTANTIABLE,
        /**
         * No bean-defining annotation: the container would not discover this class as a bean.
         */
        NOT_A_BEAN,
        /**
         * Excluded from discovery with {@code @Vetoed} (on the class or its package).
         */
        VETOED,
        /**
         * Final classes cannot be proxied by the container.
         */
        FINAL,
        /**
         * EJB session beans are managed by the EJB container and cannot be replaced by a synthetic bean.
         */
        EJB
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(SecuredTypeIndex.class);
    private static final String CLASS_SUFFIX = ".class";
    private static final List<String> PLATFORM_PREFIXES = List.of("java.", "javax.", "jakarta.", "jdk.", "sun.");
    private static final DotName VETOED = DotName.createSimple("jakarta.enterprise.inject.Vetoed");
    private static final DotName STEREOTYPE = DotName.createSimple("jakarta.enterprise.inject.Stereotype");
    private static final DotName NORMAL_SCOPE = DotName.createSimple("jakarta.enterprise.context.NormalScope");
    private static final Set<DotName> BUILT_IN_BEAN_DEFINING = Stream.of(
            "jakarta.enterprise.context.ApplicationScoped", "jakarta.enterprise.context.SessionScoped",
            "jakarta.enterprise.context.RequestScoped", "jakarta.enterprise.context.ConversationScoped",
            "jakarta.enterprise.context.Dependent", "jakarta.enterprise.inject.Model")
            .map(DotName::createSimple).collect(Collectors.toUnmodifiableSet());
    private static final Set<DotName> EJB_TYPES = Stream.of(
            "jakarta.ejb.Stateless", "jakarta.ejb.Stateful", "jakarta.ejb.Singleton", "jakarta.ejb.MessageDriven")
            .map(DotName::createSimple).collect(Collectors.toUnmodifiableSet());

    private final IndexView index;
    private final boolean indexed;
    private final Set<String> directlySecured;
    private final Set<String> indirectlySecured;
    private final Set<String> candidates;
    private final Map<String, SkipReason> skipped;

    private SecuredTypeIndex(IndexView index, boolean indexed, Collection<Class<? extends Annotation>> annotationTypes) {
        this.index = index;
        this.indexed = indexed;
        Set<DotName> annotationNames = expandMetaAnnotations(annotationTypes);
        this.directlySecured = Collections.unmodifiableSet(findDirectlySecured(annotationNames));
        this.indirectlySecured = Collections.unmodifiableSet(findIndirectlySecured());
        Map<String, SkipReason> skips = new LinkedHashMap<>();
        Set<String> accepted = new LinkedHashSet<>();
        for (String name : indirectlySecured) {
            SkipReason reason = skipReason(index.getClassByName(DotName.createSimple(name)));
            if (reason == null) {
                accepted.add(name);
            } else {
                skips.put(name, reason);
            }
        }
        this.candidates = Collections.unmodifiableSet(accepted);
        this.skipped = Collections.unmodifiableMap(skips);
    }

    /**
     * Loads and merges every {@value #INDEX_RESOURCE} visible to the class loader.
     *
     * @param classLoader     the class loader to search, typically the thread context class loader
     * @param annotationTypes the authorization annotations to look for
     * @return the index, possibly {@link #isIndexed() empty}
     */
    public static SecuredTypeIndex load(ClassLoader classLoader, Collection<Class<? extends Annotation>> annotationTypes) {
        List<IndexView> indexes = new ArrayList<>();
        try {
            for (URL url : Collections.list(classLoader.getResources(INDEX_RESOURCE))) {
                try (InputStream in = url.openStream()) {
                    indexes.add(new IndexReader(in).read());
                }
                LOGGER.debug("Loaded Jandex index {}", url);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Unable to read " + INDEX_RESOURCE, e);
        }
        return of(classLoader, annotationTypes, indexes);
    }

    /**
     * Builds the secured type index from already loaded Jandex indexes.
     *
     * @param classLoader     the class loader used to supplement missing supertypes and annotation types
     * @param annotationTypes the authorization annotations to look for
     * @param indexes         the indexes to merge
     * @return the index
     */
    public static SecuredTypeIndex of(ClassLoader classLoader, Collection<Class<? extends Annotation>> annotationTypes,
                                      Collection<IndexView> indexes) {
        if (indexes.isEmpty()) {
            LOGGER.info("No {} found; types secured only through interfaces or superclasses will not be discovered",
                    INDEX_RESOURCE);
            return new SecuredTypeIndex(CompositeIndex.create(List.of()), false, annotationTypes);
        }
        return new SecuredTypeIndex(supplement(classLoader, indexes), true, annotationTypes);
    }

    /**
     * @return whether at least one index was found
     */
    public boolean isIndexed() {
        return indexed;
    }

    /**
     * @return the merged Jandex index
     */
    public IndexView getIndex() {
        return index;
    }

    /**
     * @return names of classes and interfaces carrying an authorization annotation on the type or a method
     */
    public Set<String> directlySecured() {
        return directlySecured;
    }

    /**
     * @return names of classes that are secured only because of a supertype, see {@link #directlySecured()}
     */
    public Set<String> indirectlySecured() {
        return indirectlySecured;
    }

    /**
     * @return the subset of {@link #indirectlySecured()} that a CDI container can intercept: concrete,
     * non-final, non-vetoed classes with a bean-defining annotation that are not EJBs
     */
    public Set<String> candidates() {
        return candidates;
    }

    /**
     * @return the indirectly secured classes that are not candidates, with the reason
     */
    public Map<String, SkipReason> skipped() {
        return skipped;
    }

    private Set<DotName> expandMetaAnnotations(Collection<Class<? extends Annotation>> annotationTypes) {
        Set<DotName> names = annotationTypes.stream().map(DotName::createSimple)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        boolean changed = true;
        while (changed) {
            changed = false;
            for (ClassInfo type : index.getKnownClasses()) {
                if (type.isAnnotation() && !names.contains(type.name()) && hasAnyDeclared(type, names)) {
                    names.add(type.name());
                    changed = true;
                }
            }
        }
        return names;
    }

    private Set<String> findDirectlySecured(Set<DotName> annotationNames) {
        Set<String> result = new LinkedHashSet<>();
        for (DotName annotationName : annotationNames) {
            for (AnnotationInstance instance : index.getAnnotations(annotationName)) {
                ClassInfo declaring = declaringClass(instance.target());
                if (declaring != null && !declaring.isAnnotation()) {
                    result.add(declaring.name().toString());
                }
            }
        }
        return result;
    }

    private Set<String> findIndirectlySecured() {
        Set<String> result = new LinkedHashSet<>();
        for (String name : directlySecured) {
            DotName dotName = DotName.createSimple(name);
            ClassInfo type = index.getClassByName(dotName);
            Collection<ClassInfo> subtypes = type != null && type.isInterface()
                    ? index.getAllKnownImplementors(dotName) : index.getAllKnownSubclasses(dotName);
            subtypes.stream().map(subtype -> subtype.name().toString())
                    .filter(subtype -> !directlySecured.contains(subtype)).forEach(result::add);
        }
        return result;
    }

    private SkipReason skipReason(ClassInfo type) {
        if (type == null || type.isInterface() || type.isAnnotation() || type.isEnum() || type.isAbstract()) {
            return SkipReason.NOT_INSTANTIABLE;
        }
        if (isVetoed(type)) {
            return SkipReason.VETOED;
        }
        if (Modifier.isFinal(type.flags())) {
            return SkipReason.FINAL;
        }
        if (hasAnyDeclared(type, EJB_TYPES)) {
            return SkipReason.EJB;
        }
        return hasBeanDefiningAnnotation(type) ? null : SkipReason.NOT_A_BEAN;
    }

    private boolean isVetoed(ClassInfo type) {
        if (type.hasDeclaredAnnotation(VETOED)) {
            return true;
        }
        ClassInfo packageInfo = index.getClassByName(DotName.createSimple(type.name().packagePrefix() + ".package-info"));
        return packageInfo != null && packageInfo.hasDeclaredAnnotation(VETOED);
    }

    private boolean hasBeanDefiningAnnotation(ClassInfo type) {
        for (AnnotationInstance annotation : type.declaredAnnotations()) {
            if (BUILT_IN_BEAN_DEFINING.contains(annotation.name())) {
                return true;
            }
            ClassInfo annotationType = index.getClassByName(annotation.name());
            if (annotationType != null
                    && (annotationType.hasDeclaredAnnotation(NORMAL_SCOPE) || annotationType.hasDeclaredAnnotation(STEREOTYPE))) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasAnyDeclared(ClassInfo type, Set<DotName> annotationNames) {
        return type.declaredAnnotations().stream().anyMatch(annotation -> annotationNames.contains(annotation.name()));
    }

    private static ClassInfo declaringClass(AnnotationTarget target) {
        switch (target.kind()) {
            case CLASS:
                return target.asClass();
            case METHOD:
                return target.asMethod().declaringClass();
            default:
                return null;
        }
    }

    /**
     * Indexes, from their class files, the supertypes and annotation types referenced by indexed classes but
     * absent from the indexes, round by round until nothing new is referenced. Nothing is loaded.
     */
    private static IndexView supplement(ClassLoader classLoader, Collection<IndexView> indexes) {
        List<IndexView> all = new ArrayList<>(indexes);
        IndexView merged = CompositeIndex.create(all);
        Set<DotName> seen = new HashSet<>();
        Collection<ClassInfo> latest = merged.getKnownClasses();
        while (true) {
            Deque<DotName> pending = new ArrayDeque<>();
            IndexView current = merged;
            latest.forEach(type -> queueReferences(type, current, seen, pending));
            if (pending.isEmpty()) {
                return merged;
            }
            Indexer indexer = new Indexer();
            pending.forEach(name -> indexClass(indexer, classLoader, name));
            IndexView round = indexer.complete();
            all.add(round);
            merged = CompositeIndex.create(all);
            latest = round.getKnownClasses();
        }
    }

    private static void queueReferences(ClassInfo type, IndexView merged, Set<DotName> seen, Deque<DotName> pending) {
        Stream<DotName> annotations = type.declaredAnnotations().stream().map(AnnotationInstance::name);
        Stream<DotName> supertypes = Stream.concat(Stream.of(type.superName()), type.interfaceNames().stream());
        Stream.concat(supertypes, annotations)
                .filter(name -> name != null && !isPlatformType(name) && merged.getClassByName(name) == null && seen.add(name))
                .forEach(pending::add);
    }

    private static boolean isPlatformType(DotName name) {
        String className = name.toString();
        return PLATFORM_PREFIXES.stream().anyMatch(className::startsWith);
    }

    private static void indexClass(Indexer indexer, ClassLoader classLoader, DotName name) {
        String resource = name.toString().replace('.', '/') + CLASS_SUFFIX;
        try (InputStream in = classLoader.getResourceAsStream(resource)) {
            if (in == null) {
                LOGGER.debug("Class {} is referenced by an indexed class but not available", name);
            } else {
                indexer.index(in);
            }
        } catch (IOException e) {
            LOGGER.warn("Unable to index {}", resource, e);
        }
    }
}

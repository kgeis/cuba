/*
 * Copyright (c) 2008-2016 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.haulmont.cuba.core.sys;

import com.haulmont.chile.core.model.Instance;
import com.haulmont.chile.core.model.MetaClass;
import com.haulmont.chile.core.model.MetaProperty;
import com.haulmont.cuba.core.EntityManager;
import com.haulmont.cuba.core.Persistence;
import com.haulmont.cuba.core.entity.EmbeddableEntity;
import com.haulmont.cuba.core.entity.Entity;
import com.haulmont.cuba.core.global.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import javax.persistence.Basic;
import javax.persistence.FetchType;
import java.lang.reflect.AnnotatedElement;
import java.util.*;

/**
 * Fetches entities by views by accessing reference attributes.
 */
@Component(EntityFetcher.NAME)
public class EntityFetcher {

    public static final String NAME = "cuba_EntityFetcher";

    private Logger log = LoggerFactory.getLogger(EntityFetcher.class);

    @Inject
    protected Metadata metadata;

    @Inject
    protected ViewRepository viewRepository;

    @Inject
    protected Persistence persistence;

    @Inject
    protected EntityStates entityStates;

    /**
     * Fetch instance by view object.
     */
    public void fetch(Entity instance, View view) {
        if (view == null)
            return;
        fetch(instance, view, new HashMap<>(), false);
    }

    /**
     * Fetch instance by view name.
     */
    public void fetch(Entity instance, String viewName) {
        if (viewName == null)
            return;
        View view = viewRepository.getView(instance.getClass(), viewName);
        fetch(instance, view, new HashMap<>(), false);
    }

    /**
     * Fetch instance by view object.
     *
     * @param optimizeForDetached if true, detached objects encountered in the graph will be first checked whether all
     *                            required attributes are already loaded, and reloaded only when needed.
     *                            If the argument is false, all detached objects are reloaded anyway.
     */
    public void fetch(Entity instance, View view, boolean optimizeForDetached) {
        if (view == null)
            return;
        fetch(instance, view, new HashMap<>(), optimizeForDetached);
    }

    /**
     * Fetch instance by view name.
     *
     * @param optimizeForDetached if true, detached objects encountered in the graph will be first checked whether all
     *                            required attributes are already loaded, and reloaded only when needed.
     *                            If the argument is false, all detached objects are reloaded anyway.
     */
    public void fetch(Entity instance, String viewName, boolean optimizeForDetached) {
        if (viewName == null)
            return;
        View view = viewRepository.getView(instance.getClass(), viewName);
        fetch(instance, view, new HashMap<>(), optimizeForDetached);
    }

    protected void fetch(Entity entity, View view, Map<Instance, Set<View>> visited, boolean optimizeForDetached) {
        Set<View> views = visited.get(entity);
        if (views == null) {
            views = new HashSet<>();
            visited.put(entity, views);
        } else if (views.contains(view)) {
            return;
        }
        views.add(view);

        if (log.isTraceEnabled()) log.trace("Fetching instance " + entity);

        MetaClass metaClass = metadata.getClassNN(entity.getClass());
        for (ViewProperty property : view.getProperties()) {
            MetaProperty metaProperty = metaClass.getPropertyNN(property.getName());
            if (!metaProperty.getRange().isClass() && !isLazyFetchedLocalAttribute(metaProperty))
                continue;

            if (log.isTraceEnabled()) log.trace("Fetching property " + property.getName());

            Object value = entity.getValue(property.getName());
            View propertyView = property.getView();
            if (value != null && propertyView != null) {
                if (value instanceof Collection) {
                    for (Object item : ((Collection) value)) {
                        if (item instanceof Entity)
                            fetch((Entity) item, propertyView, visited, optimizeForDetached);
                    }
                } else if (value instanceof Entity) {
                    Entity e = (Entity) value;
                    if (PersistenceHelper.isDetached(value) && !(value instanceof EmbeddableEntity)) {
                        if (!optimizeForDetached || needReloading(e, propertyView)) {
                            if (log.isTraceEnabled()) {
                                log.trace("Object " + value + " is detached, loading it");
                            }
                            //noinspection unchecked
                            String storeName = metadata.getTools().getStoreName(e.getMetaClass());
                            EntityManager em;
                            if (storeName == null) {
                                em = persistence.getEntityManager();
                            } else {
                                em = persistence.getEntityManager(storeName);
                            }
                            value = em.find(e.getClass(), e.getId());
                            if (value == null) {
                                // the instance is most probably deleted
                                continue;
                            }
                            entity.setValue(property.getName(), value);
                            e = (Entity) value;
                        }
                    }
                    fetch(e, propertyView, visited, optimizeForDetached);
                }
            }
        }
    }

    protected boolean needReloading(Entity entity, View view) {
        for (ViewProperty viewProperty : view.getProperties()) {
            if (!entityStates.isLoaded(entity, viewProperty.getName())) {
                return true;
            }
        }
        return false;
    }

    protected boolean isLazyFetchedLocalAttribute(MetaProperty metaProperty) {
        AnnotatedElement annotatedElement = metaProperty.getAnnotatedElement();
        Basic annotation = annotatedElement.getAnnotation(Basic.class);
        return annotation != null && annotation.fetch() == FetchType.LAZY;
    }
}

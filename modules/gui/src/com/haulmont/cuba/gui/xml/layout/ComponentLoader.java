/*
 * Copyright (c) 2008 Haulmont Technology Ltd. All Rights Reserved.
 * Haulmont Technology proprietary and confidential.
 * Use is subject to license terms.

 * Author: Dmitry Abramov
 * Created: 19.12.2008 15:31:30
 * $Id$
 */
package com.haulmont.cuba.gui.xml.layout;

import com.haulmont.cuba.gui.components.Component;
import com.haulmont.cuba.gui.components.Window;
import com.haulmont.cuba.gui.components.IFrame;
import com.haulmont.cuba.gui.data.DsContext;
import org.dom4j.Element;

import java.util.Locale;
import java.util.Map;

public interface ComponentLoader {
    public interface Context {
        Map<String, Object> getParameters();
        DsContext getDSContext();

        void addLazyTask(LazyTask task);
        void executeLazyTasks();
    }

    public interface LazyTask {
        void execute(Context context, IFrame frame);
    }

    Context getContext();

    Locale getLocale();
    void setLocale(Locale locale);

    String getMessagesPack();
    void setMessagesPack(String name);

    Component loadComponent(ComponentsFactory factory, Element element) throws InstantiationException, IllegalAccessException;
}

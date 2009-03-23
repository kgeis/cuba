package com.haulmont.cuba.gui.xml.layout.loaders;

import com.haulmont.cuba.gui.components.IFrame;
import com.haulmont.cuba.gui.data.DsContext;
import com.haulmont.cuba.gui.xml.layout.ComponentLoader;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Collections;

public class ComponentLoaderContext implements ComponentLoader.Context {
    protected DsContext dsContext;
    protected IFrame frame;

    protected List<ComponentLoader.LazyTask> lazyTasks = new ArrayList<ComponentLoader.LazyTask>();
    protected Map<String, Object> parameters;

    public ComponentLoaderContext(DsContext dsContext, Map<String, Object> parameters) {
        this.dsContext = dsContext;
        this.parameters = parameters;
    }

    public Map<String, Object> getParameters() {
        return Collections.unmodifiableMap(parameters);
    }

    public DsContext getDSContext() {
        return dsContext;
    }

    public IFrame getFrame() {
        return frame;
    }

    public void setFrame(IFrame frame) {
        this.frame = frame;
    }

    public void addLazyTask(ComponentLoader.LazyTask task) {
        lazyTasks.add(task);
    }

    public void executeLazyTasks() {
        for (ComponentLoader.LazyTask task : lazyTasks) {
            task.execute(this, frame);
        }
    }
}

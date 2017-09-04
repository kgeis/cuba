/*
 * Copyright (c) 2008-2017 Haulmont.
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

package com.haulmont.cuba.gui.app.core.categories;

import com.haulmont.cuba.core.entity.LocaleHelper;
import com.haulmont.cuba.core.global.GlobalConfig;
import com.haulmont.cuba.gui.components.*;
import com.haulmont.cuba.gui.xml.layout.ComponentsFactory;

import javax.inject.Inject;
import java.util.*;

public class LocalizedNameFrame extends AbstractFrame {

    @Inject
    protected ScrollBoxLayout localesScrollBox;

    @Inject
    protected ComponentsFactory factory;

    @Inject
    protected GlobalConfig globalConfig;

    protected Map<Locale, TextField> textFieldMap;

    @Override
    public void init(Map<String, Object> params) {
        textFieldMap = new HashMap<>();
        Map<String, Locale> map = globalConfig.getAvailableLocales();
        for (Map.Entry<String, Locale> entry : map.entrySet()) {
            localesScrollBox.add(createLocaleListComponent(entry.getValue(), entry.getKey()));
        }
    }

    protected Component createLocaleListComponent(Locale locale, String key) {
        TextField valueField = factory.createComponent(TextField.class);
        valueField.setWidth("100%");
        valueField.setCaption(key + "|" + locale.toString());

        textFieldMap.put(locale, valueField);

        return valueField;
    }

    public String getValue() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Locale, TextField> entry : textFieldMap.entrySet()) {
            if (!entry.getValue().getRawValue().isEmpty()) {
                sb.append(messages.getTools().localeToString(entry.getKey()))
                        .append("=").append(entry.getValue().getRawValue()).append("\n");
            }
        }
        return sb.toString();
    }

    public void setValue(String localeBundle) {
        if (localeBundle == null) {
            return;
        }

        Map<String, String> localizedNamesMap = LocaleHelper.getLocalizedNames(localeBundle);
        for (Map.Entry<Locale, TextField> textFieldEntry : textFieldMap.entrySet()) {
            for (Map.Entry<String, String> locEntry : localizedNamesMap.entrySet()) {
                if (textFieldEntry.getKey().toString().equals(locEntry.getKey())) {
                    textFieldEntry.getValue().setValue(locEntry.getValue());
                    break;
                }
            }
        }
    }
}

/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.mgt.impl.config;

import java.util.Collections;
import java.util.Map;

/**
 * Connector Config.
 */
public class StoreConnectorConfig {

    private String connectorId;

    private String connectorType;

    private Map<String, String> properties;

    public StoreConnectorConfig() {

    }

    public StoreConnectorConfig(String connectorId, String connectorType, Map<String, String> properties) {

        this.connectorId = connectorId;
        this.connectorType = connectorType;
        this.properties = properties;
    }

    public String getConnectorId() {
        return connectorId;
    }

    public void setConnectorId(String connectorId) {
        this.connectorId = connectorId;
    }

    public String getConnectorType() {
        return connectorType;
    }

    public void setConnectorType(String connectorType) {
        this.connectorType = connectorType;
    }

    public Map<String, String> getProperties() {

        if (properties == null) {
            return Collections.emptyMap();
        }
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }
}

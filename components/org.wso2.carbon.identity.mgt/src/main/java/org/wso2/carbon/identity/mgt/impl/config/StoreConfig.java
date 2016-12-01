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

import java.util.HashMap;
import java.util.Map;

/**
 * Represents a complete configurations of the stores.
 */
public class StoreConfig {

    private boolean enableCache = true;

    private boolean enableIdentityStoreCache = true;

    private boolean enableCredentialStoreCache = true;

    private Map<String, CacheConfig> authorizationStoreCacheConfigMap = new HashMap<>();

    private Map<String, CacheConfig> identityStoreCacheConfigMap = new HashMap<>();

    private Map<String, CacheConfig> credentialStoreCacheConfigMap = new HashMap<>();

    public StoreConfig() {

    }

    public boolean isEnableCache() {
        return enableCache;
    }

    public boolean isEnableIdentityStoreCache() {
        return enableIdentityStoreCache;
    }

    public void setEnableIdentityStoreCache(boolean enableIdentityStoreCache) {
        this.enableIdentityStoreCache = enableIdentityStoreCache;
    }

    public boolean isEnableCredentialStoreCache() {
        return enableCredentialStoreCache;
    }

    public void setEnableCredentialStoreCache(boolean enableCredentialStoreCache) {
        this.enableCredentialStoreCache = enableCredentialStoreCache;
    }

    public void setEnableCache(boolean enableCache) {
        this.enableCache = enableCache;
    }

    public Map<String, CacheConfig> getAuthorizationStoreCacheConfigMap() {
        return authorizationStoreCacheConfigMap;
    }

    public void setAuthorizationStoreCacheConfigMap(Map<String, CacheConfig> authorizationStoreCacheConfigMap) {
        this.authorizationStoreCacheConfigMap = authorizationStoreCacheConfigMap;
    }

    public Map<String, CacheConfig> getIdentityStoreCacheConfigMap() {
        return identityStoreCacheConfigMap;
    }

    public void setIdentityStoreCacheConfigMap(Map<String, CacheConfig> identityStoreCacheConfigMap) {
        this.identityStoreCacheConfigMap = identityStoreCacheConfigMap;
    }

    public Map<String, CacheConfig> getCredentialStoreCacheConfigMap() {
        return credentialStoreCacheConfigMap;
    }

    public void setCredentialStoreCacheConfigMap(Map<String, CacheConfig> cradentialStoreCacheConfigMap) {
        this.credentialStoreCacheConfigMap = cradentialStoreCacheConfigMap;
    }
}

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

package org.wso2.carbon.identity.mgt.impl.internal.config.claim.mapping;

import java.util.Collections;
import java.util.List;

/**
 * Claim Mapping File.
 */
public class ClaimMappingFile {

    //List<Entry>
    private List<ClaimMappingEntry> applications;
    private List<ClaimMappingEntry> identityProviders;
    private List<ClaimMappingEntry> standards;

    public List<ClaimMappingEntry> getApplicationClaimMapping() {

        if (applications == null) {
            return Collections.emptyList();
        }
        return applications;
    }

    public void setApplicationClaimMappings(List<ClaimMappingEntry> claims) {
        this.applications = claims;
    }

    public List<ClaimMappingEntry> getIdpMappings() {

        if (identityProviders == null) {
            return Collections.emptyList();
        }
        return identityProviders;
    }

    public void setIdpMappings(List<ClaimMappingEntry> claims) {
        this.identityProviders = claims;
    }

    public List<ClaimMappingEntry> getStandardMappings() {

        if (standards == null) {
            return Collections.emptyList();
        }
        return standards;
    }

    public void setStandardMappings(List<ClaimMappingEntry> claims) {
        this.standards = claims;
    }
}

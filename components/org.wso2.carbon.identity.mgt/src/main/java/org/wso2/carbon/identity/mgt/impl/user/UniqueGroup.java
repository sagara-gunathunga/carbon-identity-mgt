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

package org.wso2.carbon.identity.mgt.impl.user;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Unique GroupImpl.
 */
public class UniqueGroup {

    private String uniqueGroupId;

    private List<GroupPartition> groupPartitions;

    public UniqueGroup(String uniqueGroupId, List<GroupPartition> groupPartitions) {

        this.uniqueGroupId = uniqueGroupId;
        this.groupPartitions = groupPartitions;
    }

    public UniqueGroup() {

    }

    public String getUniqueGroupId() {
        return uniqueGroupId;
    }

    public void setUniqueGroupId(String uniqueGroupId) {
        this.uniqueGroupId = uniqueGroupId;
    }

    public List<GroupPartition> getGroupPartitions() {

        if (groupPartitions == null) {
            return Collections.emptyList();
        }
        return groupPartitions;
    }

    public void setGroupPartitions(List<GroupPartition> groupPartitions) {
        this.groupPartitions = groupPartitions;
    }

    public void addGroupPartitions(List<GroupPartition> groupPartitions) {

        if (this.groupPartitions == null) {
            this.groupPartitions = new ArrayList<>();
        }
        this.groupPartitions.addAll(groupPartitions);
    }

    public void addGroupPartition(GroupPartition groupPartition) {

        if (this.groupPartitions == null) {
            this.groupPartitions = new ArrayList<>();
        }
        this.groupPartitions.add(groupPartition);
    }
}

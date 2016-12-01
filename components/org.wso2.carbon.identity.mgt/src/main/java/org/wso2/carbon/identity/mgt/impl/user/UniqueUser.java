/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.mgt.impl.user;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Unique UserImpl.
 */
public class UniqueUser {

    private String uniqueUserId;

    private List<UserPartition> userPartitions;

    public UniqueUser(String uniqueUserId, List<UserPartition> userPartitions) {

        this.uniqueUserId = uniqueUserId;
        this.userPartitions = userPartitions;
    }

    public UniqueUser() {

    }

    public String getUniqueUserId() {
        return uniqueUserId;
    }

    public void setUniqueUserId(String uniqueUserId) {
        this.uniqueUserId = uniqueUserId;
    }

    public List<UserPartition> getUserPartitions() {

        if (userPartitions == null) {
            return Collections.emptyList();
        }
        return userPartitions;
    }

    public void setUserPartitions(List<UserPartition> userPartitions) {
        this.userPartitions = userPartitions;
    }

    public void addUserPartitions(List<UserPartition> userPartitions) {
        if (this.userPartitions == null) {
            this.userPartitions = new ArrayList<>();
        }
        this.userPartitions.addAll(userPartitions);
    }

    public void addUserPartition(UserPartition userPartition) {
        if (this.userPartitions == null) {
            this.userPartitions = new ArrayList<>();
        }
        this.userPartitions.add(userPartition);
    }
}

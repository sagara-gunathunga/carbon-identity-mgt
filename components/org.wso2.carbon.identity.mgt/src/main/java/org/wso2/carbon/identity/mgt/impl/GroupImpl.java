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

package org.wso2.carbon.identity.mgt.impl;

import org.wso2.carbon.identity.mgt.Group;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.StoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStore;
import org.wso2.carbon.security.caas.user.core.store.IdentityStore;

import java.util.List;

/**
 * GroupImpl represents a group of users.
 */
public class GroupImpl extends Group {



    /**
     * The IdentityStore this user originates from.
     */
    private transient IdentityStore identityStore;

    /**
     * The AuthorizationStore that manages permissions of this user.
     */
    private transient AuthorizationStore authorizationStore;

    private GroupImpl(String uniqueGroupId, String domainName, IdentityStore identityStore, AuthorizationStore
            authorizationStore) {
        super(uniqueGroupId, domainName);
        this.identityStore = identityStore;
        this.authorizationStore = authorizationStore;
    }



    /**
     * Get the users assigned to this group.
     *
     * @return List of users assigned to this group.
     * @throws IdentityStoreException Identity store exception.
     */
    public List<UserImpl> getUsers() throws IdentityStoreException, GroupNotFoundException {
        return identityStore.getUsersOfGroup(getUniqueGroupId());
    }

    /**
     * Get Roles assigned to this GroupImpl.
     *
     * @return List of Roles.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public List<Role> getRoles() throws AuthorizationStoreException {
        //return authorizationStore.getRolesOfGroup(uniqueGroupId, domainName);
        return null;
    }

    /**
     * Checks whether this GroupImpl is authorized for given Permission.
     *
     * @param permission Permission to be checked.
     * @return True if authorized.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public boolean isAuthorized(Permission permission) throws AuthorizationStoreException {
        //return authorizationStore.isGroupAuthorized(uniqueGroupId, domainName, permission);
        return false;
    }

    /**
     * Checks whether the UserImpl in this GroupImpl.
     *
     * @param userId Id of the UserImpl to be checked.
     * @return True if UserImpl is in this GroupImpl.
     * @throws IdentityStoreException Identity store exception.
     */
    public boolean hasUser(String userId) throws IdentityStoreException, UserNotFoundException {
        return identityStore.isUserInGroup(userId, getUniqueGroupId());
    }

    /**
     * Checks whether this GroupImpl has the Role.
     *
     * @param roleName Name of the Role to be checked.
     * @return True if this GroupImpl has the Role.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public boolean hasRole(String roleName) throws AuthorizationStoreException {
        //TODO
        return authorizationStore.isGroupInRole(getUniqueGroupId(), null, roleName);
    }

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     *
     * @param newRoleList List of Roles needs to be assigned to this GroupImpl.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public void updateRoles(List<Role> newRoleList) throws AuthorizationStoreException {
        //authorizationStore.updateRolesInGroup(uniqueGroupId, domainName, newRoleList);
    }

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     *
     * @param assignList   List to be added to the new list.
     * @param unAssignList List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public void updateRoles(List<Role> assignList, List<Role> unAssignList) throws AuthorizationStoreException {
        //authorizationStore.updateRolesInGroup(uniqueGroupId, domainName, assignList, unAssignList);
    }

    /**
     * Change the identity store
     * @param identityStore identity store instance
     */
    public void setIdentityStore(IdentityStore identityStore) {
        this.identityStore = identityStore;
    }

    /**
     * Builder for group bean.
     */
    public static class GroupBuilder {

        private String groupId;

        private String domainName;

        private IdentityStore identityStore;

        private AuthorizationStore authorizationStore;

        public String getGroupId() {
            return groupId;
        }

        public String getDomainName() {
            return domainName;
        }

        public IdentityStore getIdentityStore() {
            return identityStore;
        }

        public AuthorizationStore getAuthorizationStore() {
            return authorizationStore;
        }

        public GroupBuilder setGroupId(String groupId) {
            this.groupId = groupId;
            return this;
        }

        public GroupBuilder setDomainName(String domainName) {
            this.domainName = domainName;
            return this;
        }

        public GroupBuilder setIdentityStore(IdentityStore identityStore) {
            this.identityStore = identityStore;
            return this;
        }

        public GroupBuilder setAuthorizationStore(AuthorizationStore authorizationStore) {
            this.authorizationStore = authorizationStore;
            return this;
        }

        public GroupImpl build() {

            //TODO add authorizationStore == null
            if (groupId == null || identityStore == null || domainName == null) {
                throw new StoreException("Required data missing for building group.");
            }

            return new GroupImpl(groupId, domainName, identityStore, authorizationStore);
        }
    }
}

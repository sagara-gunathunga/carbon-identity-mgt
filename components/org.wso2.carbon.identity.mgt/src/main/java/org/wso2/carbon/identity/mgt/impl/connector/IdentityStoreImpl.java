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

package org.wso2.carbon.identity.mgt.impl.connector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.mgt.bean.Attribute;
import org.wso2.carbon.identity.mgt.bean.Domain;
import org.wso2.carbon.identity.mgt.bean.Group;
import org.wso2.carbon.identity.mgt.bean.User;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.claim.MetaClaim;
import org.wso2.carbon.identity.mgt.claim.MetaClaimMapping;
import org.wso2.carbon.identity.mgt.context.AuthenticationContext;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreConnectorException;
import org.wso2.carbon.identity.mgt.exception.DomainException;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreClientException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreConnectorException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreServerException;
import org.wso2.carbon.identity.mgt.exception.UniqueIdResolverException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.impl.internal.IdentityMgtDataHolder;
import org.wso2.carbon.identity.mgt.dto.GroupDTO;
import org.wso2.carbon.identity.mgt.dto.UserDTO;
import org.wso2.carbon.identity.mgt.store.IdentityStore;
import org.wso2.carbon.identity.mgt.store.connector.CredentialStoreConnector;
import org.wso2.carbon.identity.mgt.impl.user.GroupPartition;
import org.wso2.carbon.identity.mgt.impl.user.UniqueGroup;
import org.wso2.carbon.identity.mgt.impl.user.UniqueUser;
import org.wso2.carbon.identity.mgt.impl.user.UserPartition;
import org.wso2.carbon.identity.mgt.impl.util.IdentityUserMgtUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.security.auth.callback.Callback;

import static org.wso2.carbon.identity.mgt.impl.util.IdentityMgtConstants.USERNAME_CLAIM;
import static org.wso2.carbon.kernel.utils.StringUtils.isNullOrEmpty;


public class IdentityStoreImpl implements IdentityStore {

    private static final Logger log = LoggerFactory.getLogger(IdentityStoreImpl.class);

    private Map<String, Domain> domainNameToDomainMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private SortedSet<Domain> sortedDomains = new TreeSet<>((d1, d2) -> {

        int d1Priority = d1.getDomainPriority();
        int d2Priority = d2.getDomainPriority();

        // Allow having multiple domains with the same priority
        if (d1Priority == d2Priority) {
            d2Priority++;
        }

        return Integer.compare(d1Priority, d2Priority);
    });

    @Override
    public void init(List<Domain> domains) throws IdentityStoreException {

        if (domains.isEmpty()) {
            throw new IdentityStoreException("No domains registered.");
        }

        sortedDomains.addAll(domains);
        domainNameToDomainMap = domains.stream()
                .filter(domain -> !isNullOrEmpty(domain.getDomainName()))
                .collect(Collectors.toMap(Domain::getDomainName, domain -> domain));

        if (log.isDebugEnabled()) {
            log.debug("Identity store successfully initialized.");
        }
    }



    @Override
    public User getUser(String uniqueUserId) throws IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid unique user id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doGetUser(uniqueUserId, domain);
    }

    @Override
    public User getUser(String uniqueUserId, String domainName) throws IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(domainName)) {
            return getUser(uniqueUserId);
        }

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid unique user id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doGetUser(uniqueUserId, domain);
    }

    //TODO:ClaimWrapper handle uniqueness validation & claim dialect conversion
    @Override
    public User getUser(Claim claim) throws IdentityStoreException, UserNotFoundException {

        if (claim == null || isNullOrEmpty(claim.getValue())) {
            throw new IdentityStoreClientException("Invalid claim.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doGetUser(claim, domain);
    }

    //TODO:ClaimWrapper handle uniqueness validation & claim dialect conversion
    @Override
    public User getUser(Claim claim, String domainName) throws IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(domainName)) {
            return getUser(claim);
        }

        if (claim == null || isNullOrEmpty(claim.getValue())) {
            throw new IdentityStoreClientException("Invalid claim.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doGetUser(claim, domain);
    }

    @Override
    public List<User> listUsers(int offset, int length) throws IdentityStoreException {

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doListUsers(offset, length, domain);
    }

    @Override
    public List<User> listUsers(int offset, int length, String domainName) throws IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            return listUsers(offset, length);
        }

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doListUsers(offset, length, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<User> listUsers(Claim claim, int offset, int length) throws IdentityStoreException {

        if (claim == null || isNullOrEmpty(claim.getValue())) {
            throw new IdentityStoreClientException("Invalid claim.");
        }

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doListUsers(claim, offset, length, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<User> listUsers(Claim claim, int offset, int length, String domainName) throws IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            return listUsers(claim, offset, length);
        }

        if (claim == null || isNullOrEmpty(claim.getValue())) {
            throw new IdentityStoreClientException("Invalid claim.");
        }

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doListUsers(claim, offset, length, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<User> listUsers(MetaClaim metaClaim, String filterPattern, int offset, int length)
            throws IdentityStoreException {

        if (metaClaim == null) {
            throw new IdentityStoreClientException("Invalid claim URI.");
        }

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doListUsers(metaClaim, filterPattern, offset, length, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<User> listUsers(MetaClaim metaClaim, String filterPattern, int offset, int length, String domainName)
            throws IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            return listUsers(metaClaim, filterPattern, offset, length);
        }

        if (metaClaim == null) {
            throw new IdentityStoreClientException("Invalid claim URI.");
        }

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doListUsers(metaClaim, filterPattern, offset, length, domain);
    }

    @Override
    public Group getGroup(String uniqueGroupId) throws IdentityStoreException, GroupNotFoundException {

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid unique group id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doGetGroup(uniqueGroupId, domain);
    }

    @Override
    public Group getGroup(String uniqueGroupId, String domainName) throws IdentityStoreException,
            GroupNotFoundException {

        if (isNullOrEmpty(domainName)) {
            return getGroup(uniqueGroupId);
        }

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid unique group id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doGetGroup(uniqueGroupId, domain);
    }

    //TODO:ClaimWrapper handle uniqueness validation & claim dialect conversion
    @Override
    public Group getGroup(Claim claim) throws IdentityStoreException, GroupNotFoundException {

        if (claim == null || isNullOrEmpty(claim.getValue())) {
            throw new IdentityStoreClientException("Invalid claim.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doGetGroup(claim, domain);
    }

    //TODO:ClaimWrapper handle uniqueness validation & claim dialect conversion
    @Override
    public Group getGroup(Claim claim, String domainName) throws IdentityStoreException, GroupNotFoundException {

        if (isNullOrEmpty(domainName)) {
            return getGroup(claim);
        }

        if (claim == null || isNullOrEmpty(claim.getValue())) {
            throw new IdentityStoreClientException("Invalid claim.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doGetGroup(claim, domain);
    }

    @Override
    public List<Group> listGroups(int offset, int length) throws IdentityStoreException {

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doListGroups(offset, length, domain);
    }

    @Override
    public List<Group> listGroups(int offset, int length, String domainName) throws IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            return listGroups(offset, length);
        }

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doListGroups(offset, length, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<Group> listGroups(Claim claim, int offset, int length) throws IdentityStoreException {

        if (claim == null || isNullOrEmpty(claim.getValue())) {
            throw new IdentityStoreClientException("Invalid claim.");
        }

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doListGroups(claim, offset, length, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<Group> listGroups(Claim claim, int offset, int length, String domainName) throws
            IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            return listGroups(claim, offset, length);
        }

        if (claim == null || isNullOrEmpty(claim.getValue())) {
            throw new IdentityStoreClientException("Invalid claim.");
        }

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doListGroups(claim, offset, length, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<Group> listGroups(MetaClaim metaClaim, String filterPattern, int offset, int length) throws
            IdentityStoreException {

        if (metaClaim == null) {
            throw new IdentityStoreClientException("Invalid claim URI.");
        }

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doListGroups(metaClaim, filterPattern, offset, length, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<Group> listGroups(MetaClaim metaClaim, String filterPattern, int offset, int length, String
            domainName) throws IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            return listGroups(metaClaim, filterPattern, offset, length);
        }

        if (metaClaim == null) {
            throw new IdentityStoreClientException("Invalid claim URI.");
        }

        if (length == 0) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doListGroups(metaClaim, filterPattern, offset, length, domain);
    }

    @Override
    public List<Group> getGroupsOfUser(String uniqueUserId) throws IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid unique user id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doGetGroupsOfUser(uniqueUserId, domain);
    }

    @Override
    public List<Group> getGroupsOfUser(String uniqueUserId, String domainName) throws IdentityStoreException,
            UserNotFoundException {

        if (isNullOrEmpty(domainName)) {
            return getGroupsOfUser(uniqueUserId);
        }

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid unique user id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doGetGroupsOfUser(uniqueUserId, domain);
    }

    @Override
    public List<User> getUsersOfGroup(String uniqueGroupId) throws IdentityStoreException, GroupNotFoundException {

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid unique group id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doGetUsersOfGroup(uniqueGroupId, domain);
    }

    @Override
    public List<User> getUsersOfGroup(String uniqueGroupId, String domainName) throws IdentityStoreException,
            GroupNotFoundException {

        if (isNullOrEmpty(domainName)) {
            return getUsersOfGroup(uniqueGroupId);
        }

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid unique group id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doGetUsersOfGroup(uniqueGroupId, domain);
    }

    @Override
    public boolean isUserInGroup(String uniqueUserId, String uniqueGroupId) throws IdentityStoreException,
            UserNotFoundException {

        if (isNullOrEmpty(uniqueUserId) || isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid inputs.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doIsUserInGroup(uniqueUserId, uniqueGroupId, domain);
    }

    @Override
    public boolean isUserInGroup(String uniqueUserId, String uniqueGroupId, String domainName) throws
            IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(domainName)) {
            return isUserInGroup(uniqueUserId, uniqueGroupId);
        }

        if (isNullOrEmpty(uniqueUserId) || isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid inputs.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doIsUserInGroup(uniqueUserId, uniqueGroupId, domain);
    }

    @Override
    public List<Claim> getClaims(String uniqueUserId) throws IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid unique user id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doGetClaims(uniqueUserId, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<Claim> getClaims(String uniqueUserId, String domainName) throws IdentityStoreException,
            UserNotFoundException {

        if (isNullOrEmpty(domainName)) {
            return getClaims(uniqueUserId);
        }

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid unique user id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doGetClaims(uniqueUserId, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<Claim> getClaims(String uniqueUserId, List<MetaClaim> metaClaims) throws IdentityStoreException,
            UserNotFoundException {

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid unique user id.");
        }

        if (metaClaims == null || metaClaims.isEmpty()) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doGetClaims(uniqueUserId, metaClaims, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<Claim> getClaims(String uniqueUserId, List<MetaClaim> metaClaims, String domainName) throws
            IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(domainName)) {
            return getClaims(uniqueUserId, metaClaims);
        }

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid unique user id.");
        }

        if (metaClaims == null || metaClaims.isEmpty()) {
            return Collections.emptyList();
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doGetClaims(uniqueUserId, metaClaims, domain);
    }

    /**
     * Identity UserImpl Management Read Operations End.
     */

    /**
     * Identity UserImpl Management Write Operations
     */

    //TODO:ClaimWrapper handle claim dialect conversion, validate username claim existence
    @Override
    public User addUser(UserDTO userModel) throws IdentityStoreException {

        if (userModel == null || (userModel.getClaims().isEmpty() && userModel.getCredentials().isEmpty())) {
            throw new IdentityStoreClientException("Invalid user.");
        }

        if (!userModel.getClaims().isEmpty() && !userModel.getClaims().stream().filter(claim -> USERNAME_CLAIM.equals
                (claim.getClaimUri()) && !isNullOrEmpty(claim.getValue())).findAny().isPresent()) {
            throw new IdentityStoreClientException("Valid username claim must be present.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doAddUser(userModel, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion, validate username claim existence
    @Override
    public User addUser(UserDTO userModel, String domainName) throws IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            return addUser(userModel);
        }

        if (userModel == null || (userModel.getClaims().isEmpty() && userModel.getCredentials().isEmpty())) {
            throw new IdentityStoreClientException("Invalid user.");
        }

        if (!userModel.getClaims().isEmpty() && !userModel.getClaims().stream().filter(claim -> USERNAME_CLAIM.equals
                (claim.getClaimUri()) && !isNullOrEmpty(claim.getValue())).findAny().isPresent()) {
            throw new IdentityStoreClientException("Valid username claim must be present.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doAddUser(userModel, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion, validate username claim existence
    @Override
    public List<User> addUsers(List<UserDTO> userModels) throws IdentityStoreException {

        if (userModels == null || userModels.isEmpty()) {
            throw new IdentityStoreClientException("Invalid user list.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doAddUsers(userModels, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion, validate username claim existence
    @Override
    public List<User> addUsers(List<UserDTO> userModels, String domainName) throws IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            return addUsers(userModels);
        }

        if (userModels == null || userModels.isEmpty()) {
            throw new IdentityStoreClientException("Invalid user list.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doAddUsers(userModels, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public void updateUserClaims(String uniqueUserId, List<Claim> claims) throws IdentityStoreException,
            UserNotFoundException {

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid user unique id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        doUpdateUserClaims(uniqueUserId, claims, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public void updateUserClaims(String uniqueUserId, List<Claim> claims, String domainName) throws
            IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(domainName)) {
            updateUserClaims(uniqueUserId, claims);
            return;
        }

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid user unique id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        doUpdateUserClaims(uniqueUserId, claims, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion,
    @Override
    public void updateUserClaims(String uniqueUserId, List<Claim> claimsToAdd, List<Claim> claimsToRemove)
            throws IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid user unique id.");
        }

        if ((claimsToAdd == null || claimsToAdd.isEmpty()) && (claimsToRemove == null || claimsToRemove.isEmpty())) {
            return;
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        doUpdateUserClaims(uniqueUserId, claimsToAdd, claimsToRemove, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion,
    @Override
    public void updateUserClaims(String uniqueUserId, List<Claim> claimsToAdd, List<Claim> claimsToRemove, String
            domainName) throws IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(domainName)) {
            updateUserClaims(uniqueUserId, claimsToAdd, claimsToRemove);
            return;
        }

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid user unique id.");
        }

        if ((claimsToAdd == null || claimsToAdd.isEmpty()) && (claimsToRemove == null || claimsToRemove.isEmpty())) {
            return;
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        doUpdateUserClaims(uniqueUserId, claimsToAdd, claimsToRemove, domain);
    }

    @Override
    public void deleteUser(String uniqueUserId) throws IdentityStoreException, UserNotFoundException {

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid user unique id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        doDeleteUser(uniqueUserId, domain);
    }

    @Override
    public void deleteUser(String uniqueUserId, String domainName) throws IdentityStoreException,
            UserNotFoundException {

        if (isNullOrEmpty(domainName)) {
            deleteUser(uniqueUserId);
            return;
        }

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid user unique id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        doDeleteUser(uniqueUserId, domain);
    }

    @Override
    public void updateGroupsOfUser(String uniqueUserId, List<String> uniqueGroupIds) throws IdentityStoreException {

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid user unique id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        try {
            domain.getUniqueIdResolver().updateGroupsOfUser(uniqueUserId, uniqueGroupIds);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to update groups of user - %s", uniqueUserId));
        }
    }

    @Override
    public void updateGroupsOfUser(String uniqueUserId, List<String> uniqueGroupIds, String domainName) throws
            IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            updateGroupsOfUser(uniqueUserId, uniqueGroupIds);
            return;
        }

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid user unique id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        try {
            domain.getUniqueIdResolver().updateGroupsOfUser(uniqueUserId, uniqueGroupIds);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to update groups of user - %s", uniqueUserId));
        }
    }

    @Override
    public void updateGroupsOfUser(String uniqueUserId, List<String> uniqueGroupIdsToAdd, List<String>
            uniqueGroupIdsToRemove) throws IdentityStoreException {

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid user unique id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        try {
            domain.getUniqueIdResolver().updateGroupsOfUser(uniqueUserId, uniqueGroupIdsToAdd, uniqueGroupIdsToRemove);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to update groups of user - %s", uniqueUserId));
        }
    }

    @Override
    public void updateGroupsOfUser(String uniqueUserId, List<String> uniqueGroupIdsToAdd, List<String>
            uniqueGroupIdsToRemove, String domainName) throws IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            updateGroupsOfUser(uniqueUserId, uniqueGroupIdsToAdd, uniqueGroupIdsToRemove);
            return;
        }

        if (isNullOrEmpty(uniqueUserId)) {
            throw new IdentityStoreClientException("Invalid user unique id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        try {
            domain.getUniqueIdResolver().updateGroupsOfUser(uniqueUserId, uniqueGroupIdsToAdd, uniqueGroupIdsToRemove);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to update groups of user - %s", uniqueUserId));
        }
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public Group addGroup(GroupDTO groupModel) throws IdentityStoreException {

        if (groupModel == null || groupModel.getClaims().isEmpty()) {
            throw new IdentityStoreClientException("Invalid group.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        return doAddGroup(groupModel, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public Group addGroup(GroupDTO groupModel, String domainName) throws IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            return addGroup(groupModel);
        }

        if (groupModel == null || groupModel.getClaims().isEmpty()) {
            throw new IdentityStoreClientException("Invalid group.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doAddGroup(groupModel, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<Group> addGroups(List<GroupDTO> groupModels) throws IdentityStoreException {

        if (groupModels == null || groupModels.isEmpty()) {
            throw new IdentityStoreClientException("Invalid group list. GroupImpl list is null or empty.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving primary domain.", e);
        }

        return doAddGroups(groupModels, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public List<Group> addGroups(List<GroupDTO> groupModels, String domainName) throws IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            return addGroups(groupModels);
        }

        if (groupModels == null || groupModels.isEmpty()) {
            throw new IdentityStoreClientException("Invalid group list. GroupImpl list is null or empty.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        return doAddGroups(groupModels, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public void updateGroupClaims(String uniqueGroupId, List<Claim> claims) throws IdentityStoreException,
            GroupNotFoundException {

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid group unique id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        doUpdateGroupClaims(uniqueGroupId, claims, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public void updateGroupClaims(String uniqueGroupId, List<Claim> claims, String domainName) throws
            IdentityStoreException, GroupNotFoundException {

        if (isNullOrEmpty(domainName)) {
            updateGroupClaims(uniqueGroupId, claims);
            return;
        }

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid group unique id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        doUpdateGroupClaims(uniqueGroupId, claims, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public void updateGroupClaims(String uniqueGroupId, List<Claim> claimsToAdd, List<Claim> claimsToRemove) throws
            IdentityStoreException, GroupNotFoundException {

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid group unique id.");
        }

        if ((claimsToAdd == null || claimsToAdd.isEmpty()) && (claimsToRemove == null || claimsToRemove.isEmpty())) {
            return;
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        doUpdateGroupClaims(uniqueGroupId, claimsToAdd, claimsToRemove, domain);
    }

    //TODO:ClaimWrapper handle claim dialect conversion
    @Override
    public void updateGroupClaims(String uniqueGroupId, List<Claim> claimsToAdd, List<Claim>
            claimsToRemove, String domainName) throws IdentityStoreException, GroupNotFoundException {

        if (isNullOrEmpty(domainName)) {
            updateGroupClaims(uniqueGroupId, claimsToAdd, claimsToRemove);
            return;
        }

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid group unique id.");
        }

        if ((claimsToAdd == null || claimsToAdd.isEmpty()) && (claimsToRemove == null || claimsToRemove.isEmpty())) {
            return;
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        doUpdateGroupClaims(uniqueGroupId, claimsToAdd, claimsToRemove, domain);
    }

    @Override
    public void deleteGroup(String uniqueGroupId) throws IdentityStoreException, GroupNotFoundException {

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid group unique id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        doDeleteGroup(uniqueGroupId, domain);
    }

    @Override
    public void deleteGroup(String uniqueGroupId, String domainName) throws IdentityStoreException,
            GroupNotFoundException {

        if (isNullOrEmpty(domainName)) {
            deleteGroup(uniqueGroupId);
            return;
        }

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid group unique id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        doDeleteGroup(uniqueGroupId, domain);
    }

    @Override
    public void updateUsersOfGroup(String uniqueGroupId, List<String> uniqueUserIds) throws IdentityStoreException {

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid group unique id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        try {
            domain.getUniqueIdResolver().updateUsersOfGroup(uniqueGroupId, uniqueUserIds);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to update users of group - %s",
                    uniqueGroupId));
        }
    }

    @Override
    public void updateUsersOfGroup(String uniqueGroupId, List<String> uniqueUserIds, String domainName) throws
            IdentityStoreException {

        if (isNullOrEmpty(domainName)) {
            updateUsersOfGroup(uniqueGroupId, uniqueUserIds);
            return;
        }

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid group unique id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        try {
            domain.getUniqueIdResolver().updateUsersOfGroup(uniqueGroupId, uniqueUserIds);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to update users of group - %s",
                    uniqueGroupId));
        }
    }

    @Override
    public void updateUsersOfGroup(String uniqueGroupId, List<String> uniqueUserIdsToAdd, List<String>
            uniqueUserIdsToRemove) throws IdentityStoreException {

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid group unique id.");
        }

        Domain domain;
        try {
            domain = getPrimaryDomain();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Error while retrieving the primary domain.", e);
        }

        try {
            domain.getUniqueIdResolver().updateUsersOfGroup(uniqueGroupId, uniqueUserIdsToAdd, uniqueUserIdsToRemove);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to update users of group - %s",
                    uniqueGroupId));
        }
    }

    @Override
    public void updateUsersOfGroup(String uniqueGroupId, List<String> uniqueUserIdsToAdd, List<String>
            uniqueUserIdsToRemove, String domainName) throws IdentityStoreException {


        if (isNullOrEmpty(domainName)) {
            updateUsersOfGroup(uniqueGroupId, uniqueUserIdsToAdd, uniqueUserIdsToRemove);
            return;
        }

        if (isNullOrEmpty(uniqueGroupId)) {
            throw new IdentityStoreClientException("Invalid group unique id.");
        }

        Domain domain;
        try {
            domain = getDomainFromDomainName(domainName);
        } catch (DomainException e) {
            throw new IdentityStoreServerException(String.format("Error while retrieving domain from the domain name " +
                    "- %s", domainName), e);
        }

        try {
            domain.getUniqueIdResolver().updateUsersOfGroup(uniqueGroupId, uniqueUserIdsToAdd, uniqueUserIdsToRemove);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to update users of group - %s",
                    uniqueGroupId));
        }
    }

    /**
     * Identity UserImpl Management Write Operations End.
     */

    /**
     * Identity UserImpl Management Authentication Related Operations.
     */

    @Override
    public AuthenticationContext authenticate(Claim claim, Callback[] credentials, String domainName)
            throws AuthenticationFailure {

        if (claim == null || isNullOrEmpty(claim.getValue()) || credentials == null || credentials.length == 0) {
            throw new AuthenticationFailure("Invalid user credentials.");
        }

        if (!isNullOrEmpty(domainName)) {

            Domain domain;
            try {
                domain = getDomainFromDomainName(domainName);
            } catch (DomainException e) {
                log.error(String.format("Error while retrieving domain from the domain name - %s", domainName), e);
                throw new AuthenticationFailure(String.format("Invalid domain name - %s.", domainName));
            }
            return doAuthenticate(claim, credentials, domain);
        }

        AuthenticationContext context = null;
        for (Domain domain : sortedDomains) {
            if (domain.isClaimSupported(claim.getClaimUri())) {
                try {
                    context = doAuthenticate(claim, credentials, domain);
                    break;
                } catch (AuthenticationFailure e) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Failed to authenticate user - %s from domain - %s", claim.getValue(),
                                domainName), e);
                    }
                }
            }
        }

        if (context == null) {
            throw new AuthenticationFailure("Invalid user credentials.");
        }
        return context;
    }

    /**
     * Identity UserImpl Management Authentication Related Operations End.
     */

    /**
     * Identity UserImpl Management Domain Read Operations.
     */

    @Override
    public String getPrimaryDomainName() throws IdentityStoreException {

        Domain domain = sortedDomains.first();

        if (domain == null) {
            throw new IdentityStoreServerException("No domains registered.");
        }

        return domain.getDomainName();
    }

    @Override
    public Set<String> getDomainNames() throws IdentityStoreException {

        Set<String> domainNames = domainNameToDomainMap.keySet();

        if (domainNames.isEmpty()) {
            throw new IdentityStoreServerException("No domains registered.");
        }

        return domainNameToDomainMap.keySet();
    }

    /**
     * Identity UserImpl Management Domain Read End.
     */

    /**
     * Identity UserImpl Management private methods.
     */

    private User doGetUser(String uniqueUserId, Domain domain) throws IdentityStoreException, UserNotFoundException {

        boolean userExists;
        try {
            userExists = domain.getUniqueIdResolver().isUserExists(uniqueUserId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to check existence of unique user - " +
                    "%s.", uniqueUserId), e);
        }

        if (!userExists) {
            throw new UserNotFoundException("Invalid unique user id.");
        }

        return new User.UserBuilder()
                .setUserId(uniqueUserId)
                .setDomainName(domain.getDomainName())
                .setIdentityStore(this)
                .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                .build();
    }

    private User doGetUser(Claim claim, Domain domain) throws IdentityStoreException, UserNotFoundException {

        MetaClaimMapping metaClaimMapping;
        try {
            metaClaimMapping = domain.getMetaClaimMapping(claim.getClaimUri());
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve the meta claim mapping for the claim URI.");
        }

        String connectorUserId;
        try {
            connectorUserId = domain.getIdentityStoreConnectorFromId(metaClaimMapping.getIdentityStoreConnectorId())
                    .getConnectorUserId(metaClaimMapping.getAttributeName(), claim.getValue());
        } catch (IdentityStoreConnectorException e) {
            throw new IdentityStoreServerException("Failed to get connector user id", e);
        }

        if (isNullOrEmpty(connectorUserId)) {
            throw new UserNotFoundException("Invalid claim value.");
        }

        UniqueUser uniqueUser;
        try {
            uniqueUser = domain.getUniqueIdResolver().getUniqueUserFromConnectorUserId(connectorUserId, metaClaimMapping
                    .getIdentityStoreConnectorId());
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException("Failed to retrieve the unique user id.", e);
        }

        if (uniqueUser == null || isNullOrEmpty(uniqueUser.getUniqueUserId())) {
            throw new IdentityStoreServerException("Failed to retrieve the unique user id.");
        }

        return new User.UserBuilder()
                .setUserId(uniqueUser.getUniqueUserId())
                .setDomainName(domain.getDomainName())
                .setIdentityStore(this)
                .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                .build();
    }

    private List<User> doListUsers(int offset, int length, Domain domain) throws IdentityStoreException {

        List<UniqueUser> uniqueUsers;
        try {
            uniqueUsers = domain.getUniqueIdResolver().listUsers(offset, length);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to list users in the domain - %s", domain), e);
        }

        if (uniqueUsers == null || uniqueUsers.isEmpty()) {
            return Collections.emptyList();
        }

        return uniqueUsers.stream()
                .map(uniqueUser -> new User.UserBuilder()
                        .setUserId(uniqueUser.getUniqueUserId())
                        .setDomainName(domain.getDomainName())
                        .setIdentityStore(this)
                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    private List<User> doListUsers(Claim claim, int offset, int length, Domain domain) throws IdentityStoreException {

        MetaClaimMapping metaClaimMapping;
        try {
            metaClaimMapping = domain.getMetaClaimMapping(claim.getClaimUri());
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve the meta claim mapping for the claim URI.");
        }

        List<String> connectorUserIds;
        try {
            connectorUserIds = domain.getIdentityStoreConnectorFromId(metaClaimMapping
                    .getIdentityStoreConnectorId()).listConnectorUserIds(metaClaimMapping.getAttributeName(), claim
                    .getValue(), offset, length);
        } catch (IdentityStoreConnectorException e) {
            throw new IdentityStoreServerException("Failed to list connector user ids", e);
        }

        if (connectorUserIds == null || connectorUserIds.isEmpty()) {
            return Collections.emptyList();
        }

        List<UniqueUser> uniqueUsers;
        try {
            uniqueUsers = domain.getUniqueIdResolver().getUniqueUsers(connectorUserIds, metaClaimMapping
                    .getIdentityStoreConnectorId());
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException("Failed to retrieve the unique user ids.", e);
        }

        if (uniqueUsers == null || uniqueUsers.isEmpty()) {
            throw new IdentityStoreServerException("Failed to retrieve the unique user ids.");
        }

        return uniqueUsers.stream()
                .map(uniqueUser -> new User.UserBuilder()
                        .setUserId(uniqueUser.getUniqueUserId())
                        .setDomainName(domain.getDomainName())
                        .setIdentityStore(this)
                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    private List<User> doListUsers(MetaClaim metaClaim, String filterPattern, int offset, int length, Domain domain)
            throws IdentityStoreException {

        MetaClaimMapping metaClaimMapping;
        try {
            metaClaimMapping = domain.getMetaClaimMapping(metaClaim.getClaimUri());
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve the meta claim mapping for the claim URI.");
        }

        List<String> connectorUserIds;
        try {
            connectorUserIds = domain.getIdentityStoreConnectorFromId(metaClaimMapping
                    .getIdentityStoreConnectorId()).listConnectorUserIdsByPattern(metaClaimMapping.getAttributeName(),
                    filterPattern, offset, length);
        } catch (IdentityStoreConnectorException e) {
            throw new IdentityStoreServerException("Failed to list connector user ids by pattern", e);
        }

        if (connectorUserIds == null || connectorUserIds.isEmpty()) {
            return Collections.emptyList();
        }

        List<UniqueUser> uniqueUsers;
        try {
            uniqueUsers = domain.getUniqueIdResolver().getUniqueUsers(connectorUserIds, metaClaimMapping
                    .getIdentityStoreConnectorId());
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException("Failed to retrieve the unique user ids.", e);
        }

        if (uniqueUsers == null || uniqueUsers.isEmpty()) {
            throw new IdentityStoreServerException("Failed to retrieve the unique user ids.");
        }

        return uniqueUsers.stream()
                .map(uniqueUser -> new User.UserBuilder()
                        .setUserId(uniqueUser.getUniqueUserId())
                        .setDomainName(domain.getDomainName())
                        .setIdentityStore(this)
                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    private Group doGetGroup(String uniqueGroupId, Domain domain) throws IdentityStoreException,
            GroupNotFoundException {

        boolean groupExists;
        try {
            groupExists = domain.getUniqueIdResolver().isGroupExists(uniqueGroupId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to check existence of unique group - " +
                    "%s.", uniqueGroupId), e);
        }

        if (!groupExists) {
            throw new GroupNotFoundException("Invalid unique group id.");
        }

        return new Group.GroupBuilder()
                .setGroupId(uniqueGroupId)
                .setDomainName(domain.getDomainName())
                .setIdentityStore(this)
                .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                .build();
    }

    private Group doGetGroup(Claim claim, Domain domain) throws IdentityStoreException, GroupNotFoundException {

        MetaClaimMapping metaClaimMapping;
        try {
            metaClaimMapping = domain.getMetaClaimMapping(claim.getClaimUri());
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve the meta claim mapping for the claim URI.");
        }

        String connectorGroupId;
        try {
            connectorGroupId = domain.getIdentityStoreConnectorFromId(metaClaimMapping.getIdentityStoreConnectorId())
                    .getConnectorGroupId(metaClaimMapping.getAttributeName(), claim.getValue());
        } catch (IdentityStoreConnectorException e) {
            throw new IdentityStoreServerException("Failed to get connector group id", e);
        }

        if (isNullOrEmpty(connectorGroupId)) {
            throw new GroupNotFoundException("Invalid claim value.");
        }

        UniqueGroup uniqueGroup;
        try {
            uniqueGroup = domain.getUniqueIdResolver().getUniqueGroupFromConnectorGroupId(connectorGroupId,
                    metaClaimMapping.getIdentityStoreConnectorId());
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException("Failed retrieve the group unique id.", e);
        }

        if (uniqueGroup == null || isNullOrEmpty(uniqueGroup.getUniqueGroupId())) {
            throw new IdentityStoreServerException("Failed to retrieve the unique group id.");
        }

        return new Group.GroupBuilder()
                .setGroupId(uniqueGroup.getUniqueGroupId())
                .setDomainName(domain.getDomainName())
                .setIdentityStore(this)
                .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                .build();
    }

    private List<Group> doListGroups(int offset, int length, Domain domain) throws IdentityStoreException {

        List<UniqueGroup> uniqueGroups;
        try {
            uniqueGroups = domain.getUniqueIdResolver().listGroups(offset, length);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to list groups in the domain - %s", domain),
                    e);
        }

        if (uniqueGroups == null || uniqueGroups.isEmpty()) {
            return Collections.emptyList();
        }

        return uniqueGroups.stream()
                .map(uniqueGroup -> new Group.GroupBuilder()
                        .setGroupId(uniqueGroup.getUniqueGroupId())
                        .setDomainName(domain.getDomainName())
                        .setIdentityStore(this)
                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    private List<Group> doListGroups(Claim claim, int offset, int length, Domain domain) throws IdentityStoreException {

        MetaClaimMapping metaClaimMapping;
        try {
            metaClaimMapping = domain.getMetaClaimMapping(claim.getClaimUri());
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve the meta claim mapping for the claim URI.");
        }

        List<String> connectorGroupIds;
        try {
            connectorGroupIds = domain.getIdentityStoreConnectorFromId(metaClaimMapping
                    .getIdentityStoreConnectorId()).listConnectorGroupIds(metaClaimMapping.getAttributeName(), claim
                    .getValue(), offset, length);
        } catch (IdentityStoreConnectorException e) {
            throw new IdentityStoreServerException("Failed to list connector group ids", e);
        }

        if (connectorGroupIds == null || connectorGroupIds.isEmpty()) {
            return Collections.emptyList();
        }

        List<UniqueGroup> uniqueGroups;
        try {
            uniqueGroups = domain.getUniqueIdResolver().getUniqueGroups(connectorGroupIds, metaClaimMapping
                    .getIdentityStoreConnectorId());
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException("Failed to retrieve the unique group ids.", e);
        }

        if (uniqueGroups == null || uniqueGroups.isEmpty()) {
            throw new IdentityStoreServerException("Failed to retrieve the unique group ids.");
        }

        return uniqueGroups.stream()
                .map(uniqueGroup -> new Group.GroupBuilder()
                        .setGroupId(uniqueGroup.getUniqueGroupId())
                        .setDomainName(domain.getDomainName())
                        .setIdentityStore(this)
                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    private List<Group> doListGroups(MetaClaim metaClaim, String filterPattern, int offset, int length, Domain domain)
            throws IdentityStoreException {

        MetaClaimMapping metaClaimMapping;
        try {
            metaClaimMapping = domain.getMetaClaimMapping(metaClaim.getClaimUri());
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve the meta claim mapping for the claim URI.");
        }

        List<String> connectorGroupIds;
        try {
            connectorGroupIds = domain.getIdentityStoreConnectorFromId(metaClaimMapping
                    .getIdentityStoreConnectorId()).listConnectorGroupIdsByPattern(metaClaimMapping.getAttributeName(),
                    filterPattern, offset, length);
        } catch (IdentityStoreConnectorException e) {
            throw new IdentityStoreServerException("Failed to list connector group ids by pattern", e);
        }

        if (connectorGroupIds == null || connectorGroupIds.isEmpty()) {
            return Collections.emptyList();
        }

        List<UniqueGroup> uniqueGroups;
        try {
            uniqueGroups = domain.getUniqueIdResolver().getUniqueGroups(connectorGroupIds, metaClaimMapping
                    .getIdentityStoreConnectorId());
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException("Failed to retrieve the unique group ids.", e);
        }

        if (uniqueGroups == null || uniqueGroups.isEmpty()) {
            throw new IdentityStoreServerException("Failed to retrieve the unique group ids.");
        }

        return uniqueGroups.stream()
                .map(uniqueGroup -> new Group.GroupBuilder()
                        .setGroupId(uniqueGroup.getUniqueGroupId())
                        .setDomainName(domain.getDomainName())
                        .setIdentityStore(this)
                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    private List<Group> doGetGroupsOfUser(String uniqueUserId, Domain domain) throws IdentityStoreException,
            UserNotFoundException {

        boolean userExists;
        try {
            userExists = domain.getUniqueIdResolver().isUserExists(uniqueUserId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to check existence of unique user - " +
                    "%s.", uniqueUserId), e);
        }

        if (!userExists) {
            throw new UserNotFoundException("Invalid unique user id.");
        }

        List<UniqueGroup> uniqueGroups;
        try {
            uniqueGroups = domain.getUniqueIdResolver().getGroupsOfUser(uniqueUserId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to retrieve the unique group ids for user id" +
                    " - %s.", uniqueUserId), e);
        }

        if (uniqueGroups == null || uniqueGroups.isEmpty()) {
            return Collections.emptyList();
        }

        return uniqueGroups.stream()
                .map(uniqueGroup -> new Group.GroupBuilder()
                        .setGroupId(uniqueGroup.getUniqueGroupId())
                        .setDomainName(domain.getDomainName())
                        .setIdentityStore(this)
                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    private List<User> doGetUsersOfGroup(String uniqueGroupId, Domain domain) throws IdentityStoreException,
            GroupNotFoundException {

        boolean groupExists;
        try {
            groupExists = domain.getUniqueIdResolver().isGroupExists(uniqueGroupId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to check existence of unique group - " +
                    "%s.", uniqueGroupId), e);
        }

        if (!groupExists) {
            throw new GroupNotFoundException("Invalid unique group id.");
        }

        List<UniqueUser> uniqueUsers;
        try {
            uniqueUsers = domain.getUniqueIdResolver().getUsersOfGroup(uniqueGroupId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to retrieve the unique user ids for group id" +
                    " - %s.", uniqueGroupId), e);
        }

        if (uniqueUsers == null || uniqueUsers.isEmpty()) {
            return Collections.emptyList();
        }

        return uniqueUsers.stream()
                .map(uniqueUser -> new User.UserBuilder()
                        .setUserId(uniqueUser.getUniqueUserId())
                        .setDomainName(domain.getDomainName())
                        .setIdentityStore(this)
                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    private boolean doIsUserInGroup(String uniqueUserId, String uniqueGroupId, Domain domain) throws
            IdentityStoreException, UserNotFoundException {

        boolean userExists;
        try {
            userExists = domain.getUniqueIdResolver().isUserExists(uniqueUserId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to check existence of unique user - " +
                    "%s.", uniqueUserId), e);
        }

        if (!userExists) {
            throw new UserNotFoundException("Invalid unique user id.");
        }

        try {
            return domain.getUniqueIdResolver().isUserInGroup(uniqueUserId, uniqueGroupId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to check unique user - %s belong to the " +
                    "group -  %s.", uniqueUserId, uniqueGroupId), e);
        }
    }

    private List<Claim> doGetClaims(String uniqueUserId, Domain domain) throws IdentityStoreException,
            UserNotFoundException {

        UniqueUser uniqueUser;
        try {
            uniqueUser = domain.getUniqueIdResolver().getUniqueUser(uniqueUserId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to retrieve unique user - " +
                    "%s.", uniqueUserId), e);
        }

        if (uniqueUser == null) {
            throw new UserNotFoundException("Invalid unique user id.");
        }

        if (uniqueUser.getUserPartitions() == null || uniqueUser.getUserPartitions().isEmpty()) {
            return Collections.emptyList();
        }

        List<UserPartition> userPartitions = uniqueUser.getUserPartitions().stream()
                .filter(UserPartition::isIdentityStore)
                .collect(Collectors.toList());

        if (userPartitions.isEmpty()) {
            return Collections.emptyList();
        }

        Map<String, List<Attribute>> connectorIdToAttributesMap = new HashMap<>();
        for (UserPartition userPartition : userPartitions) {
            try {
                connectorIdToAttributesMap.put(userPartition.getConnectorId(),
                        domain.getIdentityStoreConnectorFromId(userPartition.getConnectorId()).getUserAttributeValues
                                (userPartition.getConnectorUserId()));
            } catch (IdentityStoreConnectorException e) {
                throw new IdentityStoreServerException("Failed to get user attribute values", e);
            }
        }

        List<MetaClaimMapping> metaClaimMappings;
        try {
            metaClaimMappings = domain.getMetaClaimMappings();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve the meta claim mappings.");
        }

        return buildClaims(metaClaimMappings, connectorIdToAttributesMap);
    }

    private List<Claim> doGetClaims(String uniqueUserId, List<MetaClaim> metaClaims, Domain domain) throws
            IdentityStoreException,
            UserNotFoundException {

        UniqueUser uniqueUser;
        try {
            uniqueUser = domain.getUniqueIdResolver().getUniqueUser(uniqueUserId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to retrieve unique user - " +
                    "%s.", uniqueUserId), e);
        }

        if (uniqueUser == null) {
            throw new UserNotFoundException("Invalid unique user id.");
        }

        if (uniqueUser.getUserPartitions() == null || uniqueUser.getUserPartitions().isEmpty()) {
            return Collections.emptyList();
        }

        List<UserPartition> userPartitions = uniqueUser.getUserPartitions().stream()
                .filter(UserPartition::isIdentityStore)
                .collect(Collectors.toList());

        if (userPartitions.isEmpty()) {
            return Collections.emptyList();
        }

        List<MetaClaimMapping> metaClaimMappings;
        try {
            metaClaimMappings = domain.getMetaClaimMappings();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve the meta claim mappings.");
        }

        Map<String, List<String>> connectorIdToAttributeNameMap = getConnectorIdToAttributeNameMap(metaClaimMappings,
                metaClaims);

        Map<String, List<Attribute>> connectorIdToAttributesMap = new HashMap<>();
        for (UserPartition userPartition : userPartitions) {
            List<String> attributeNames = connectorIdToAttributeNameMap.get(userPartition.getConnectorId());
            if (attributeNames != null) {
                try {
                    connectorIdToAttributesMap.put(userPartition.getConnectorId(),
                            domain.getIdentityStoreConnectorFromId(userPartition.getConnectorId())
                                    .getUserAttributeValues(userPartition.getConnectorUserId(), attributeNames));
                } catch (IdentityStoreConnectorException e) {
                    throw new IdentityStoreServerException("Failed to get user attribute values.", e);
                }
            }
        }

        return buildClaims(metaClaimMappings, connectorIdToAttributesMap);
    }

    private User doAddUser(UserDTO userModel, Domain domain) throws IdentityStoreException {

        List<UserPartition> userPartitions = new ArrayList<>();

        if (!userModel.getClaims().isEmpty()) {
            List<MetaClaimMapping> metaClaimMappings;
            try {
                metaClaimMappings = domain.getMetaClaimMappings();
            } catch (DomainException e) {
                throw new IdentityStoreServerException("Failed to retrieve meta claim mappings.");
            }

            Map<String, List<Attribute>> connectorIdToAttributesMap = getConnectorIdToAttributesMap(userModel
                    .getClaims(), metaClaimMappings);


            for (Map.Entry<String, List<Attribute>> entry : connectorIdToAttributesMap.entrySet()) {
                String connectorUserId;
                try {
                    connectorUserId = domain.getIdentityStoreConnectorFromId(entry.getKey()).addUser(entry.getValue());
                } catch (IdentityStoreConnectorException e) {
                    // Recover from the inconsistent state in the connectors
                    if (userPartitions.size() > 0) {
                        removeAddedUsersInAFailure(domain, userPartitions);
                    }
                    throw new IdentityStoreServerException("Identity store connector failed to add user attributes.",
                            e);
                }

                userPartitions.add(new UserPartition(entry.getKey(), connectorUserId, true));
            }
        }

        if (!userModel.getCredentials().isEmpty()) {
            Map<String, List<Callback>> connectorIdToCredentialsMap = getConnectorIdToCredentialsMap(userModel
                    .getCredentials(), domain.getCredentialStoreConnectors());
            for (Map.Entry<String, List<Callback>> entry : connectorIdToCredentialsMap.entrySet()) {

                String connectorUserId;
                try {
                    connectorUserId = domain.getCredentialStoreConnectorFromId(entry.getKey()).addCredential(
                            entry.getValue().toArray(new Callback[entry.getValue().size()]));
                } catch (CredentialStoreConnectorException e) {
                    // Recover from the inconsistent state in the connectors
                    if (userPartitions.size() > 0) {
                        removeAddedUsersInAFailure(domain, userPartitions);
                    }
                    throw new IdentityStoreServerException("Credential store connector failed to add user attributes" +
                            ".", e);
                }

                userPartitions.add(new UserPartition(entry.getKey(), connectorUserId, false));
            }
        }

        String userUniqueId = IdentityUserMgtUtil.generateUUID();
        try {
            domain.getUniqueIdResolver().addUser(new UniqueUser(userUniqueId, userPartitions), domain.getDomainName());
        } catch (UniqueIdResolverException e) {
            // Recover from the inconsistent state in the connectors
            removeAddedUsersInAFailure(domain, userPartitions);

            throw new IdentityStoreServerException("Error occurred while persisting user unique id.", e);
        }

        return new User.UserBuilder()
                .setUserId(userUniqueId)
                .setDomainName(domain.getDomainName())
                .setIdentityStore(this)
                .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                .build();
    }

    private List<User> doAddUsers(List<UserDTO> userModels, Domain domain) throws IdentityStoreException {

        List<MetaClaimMapping> metaClaimMappings;
        try {
            metaClaimMappings = domain.getMetaClaimMappings();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve meta claim mappings.");
        }

        Map<String, UserDTO> uniqueUserIdToUserModelMap = userModels.stream()
                .filter(Objects::nonNull)
                .filter(userModel -> !userModel.getClaims().isEmpty() || !userModel.getCredentials().isEmpty())
                .collect(Collectors.toMap(userModel -> IdentityUserMgtUtil.generateUUID(), userModel -> userModel));

        Map<String, Map<String, List<Attribute>>> connectorIdToUniqueUserIdToAttributesMap = new HashMap<>();
        Map<String, Map<String, List<Callback>>> connectorIdToUniqueUserIdToCredentialMap = new HashMap<>();

        uniqueUserIdToUserModelMap.entrySet().stream()
                .filter(Objects::nonNull)
                .forEach(userModelEntry -> {

                    Map<String, List<Attribute>> connectorIdToAttributesMap = getConnectorIdToAttributesMap
                            (userModelEntry.getValue().getClaims(), metaClaimMappings);

                    if (!connectorIdToAttributesMap.isEmpty()) {
                        connectorIdToAttributesMap.entrySet().stream()
                                .forEach(attributeEntry -> {
                                            Map<String, List<Attribute>> uniqueUserIdToAttributesMap =
                                                    connectorIdToUniqueUserIdToAttributesMap.get(attributeEntry
                                                            .getKey());
                                            if (uniqueUserIdToAttributesMap == null) {
                                                uniqueUserIdToAttributesMap = new HashMap<>();
                                                connectorIdToUniqueUserIdToAttributesMap.put(attributeEntry.getKey(),
                                                        uniqueUserIdToAttributesMap);
                                            }
                                            uniqueUserIdToAttributesMap.put(userModelEntry.getKey(), attributeEntry
                                                    .getValue());
                                        }
                                );
                    }

                    Map<String, List<Callback>> connectorIdToCredentialsMap = getConnectorIdToCredentialsMap
                            (userModelEntry.getValue().getCredentials(), domain.getCredentialStoreConnectors());

                    if (!connectorIdToCredentialsMap.isEmpty()) {
                        connectorIdToCredentialsMap.entrySet().stream()
                                .forEach(credentialEntry -> {
                                            Map<String, List<Callback>> uniqueUserIdToCredentialMap =
                                                    connectorIdToUniqueUserIdToCredentialMap.get(credentialEntry
                                                            .getKey());
                                            if (uniqueUserIdToCredentialMap == null) {
                                                uniqueUserIdToCredentialMap = new HashMap<>();
                                                connectorIdToUniqueUserIdToCredentialMap.put(credentialEntry.getKey(),
                                                        uniqueUserIdToCredentialMap);
                                            }
                                            uniqueUserIdToCredentialMap.put(userModelEntry.getKey(), credentialEntry
                                                    .getValue());
                                        }
                                );
                    }
                });

        Map<String, List<UserPartition>> uniqueUserIdToUserPartitionsMap = new HashMap<>();
        if (!connectorIdToUniqueUserIdToAttributesMap.isEmpty()) {
            for (Map.Entry<String, Map<String, List<Attribute>>> entry : connectorIdToUniqueUserIdToAttributesMap
                    .entrySet()) {

                Map<String, String> uniqueUserIds;
                try {
                    uniqueUserIds = domain.getIdentityStoreConnectorFromId(entry.getKey()).addUsers(entry.getValue());
                } catch (IdentityStoreConnectorException e) {
                    if (!uniqueUserIdToUserPartitionsMap.isEmpty()) {
                        uniqueUserIdToUserPartitionsMap.entrySet().stream()
                                .forEach(partitionEntry -> removeAddedUsersInAFailure(domain,
                                        partitionEntry.getValue()));
                    }
                    throw new IdentityStoreServerException("Failed to add users.", e);
                }
                if (uniqueUserIds != null) {
                    uniqueUserIds.entrySet().stream()
                            .forEach(uniqueUserId -> {
                                List<UserPartition> userPartitions = uniqueUserIdToUserPartitionsMap.get(uniqueUserId
                                        .getKey());
                                if (userPartitions == null) {
                                    userPartitions = new ArrayList<>();
                                    uniqueUserIdToUserPartitionsMap.put(uniqueUserId.getKey(), userPartitions);
                                }
                                userPartitions.add(new UserPartition(entry.getKey(), uniqueUserId.getValue(), true));
                            });
                }
            }
        }

        if (!connectorIdToUniqueUserIdToCredentialMap.isEmpty()) {
            for (Map.Entry<String, Map<String, List<Callback>>> entry : connectorIdToUniqueUserIdToCredentialMap
                    .entrySet()) {

                Map<String, String> uniqueUserIds;
                try {
                    uniqueUserIds = domain.getCredentialStoreConnectorFromId(entry.getKey()).addCredentials(entry
                            .getValue());
                } catch (CredentialStoreConnectorException e) {
                    if (!uniqueUserIdToUserPartitionsMap.isEmpty()) {
                        uniqueUserIdToUserPartitionsMap.entrySet().stream()
                                .forEach(partitionEntry -> removeAddedUsersInAFailure(domain,
                                        partitionEntry.getValue()));
                    }
                    throw new IdentityStoreServerException("Failed to add users.", e);
                }

                if (uniqueUserIds != null) {
                    uniqueUserIds.entrySet().stream()
                            .forEach(uniqueUserId -> {
                                List<UserPartition> userPartitions = uniqueUserIdToUserPartitionsMap.get(uniqueUserId
                                        .getKey());
                                if (userPartitions == null) {
                                    userPartitions = new ArrayList<>();
                                    uniqueUserIdToUserPartitionsMap.put(uniqueUserId.getKey(), userPartitions);
                                }
                                userPartitions.add(new UserPartition(entry.getKey(), uniqueUserId.getValue(), false));
                            });
                }
            }
        }

        List<UniqueUser> uniqueUsers = uniqueUserIdToUserPartitionsMap.entrySet().stream()
                .map(entry -> new UniqueUser(entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());

        try {
            domain.getUniqueIdResolver().addUsers(uniqueUsers, domain.getDomainName());
        } catch (UniqueIdResolverException e) {
            if (!uniqueUserIdToUserPartitionsMap.isEmpty()) {
                uniqueUserIdToUserPartitionsMap.entrySet().stream()
                        .forEach(partitionEntry -> removeAddedUsersInAFailure(domain, partitionEntry.getValue()));
            }
            throw new IdentityStoreServerException("Error occurred while persisting user unique ids.", e);
        }

        return uniqueUsers.stream()
                .map(uniqueUser -> new User.UserBuilder()
                        .setUserId(uniqueUser.getUniqueUserId())
                        .setDomainName(domain.getDomainName())
                        .setIdentityStore(this)
                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    private void doUpdateUserClaims(String uniqueUserId, List<Claim> claims, Domain domain) throws
            IdentityStoreException, UserNotFoundException {

        UniqueUser uniqueUser;
        try {
            uniqueUser = domain.getUniqueIdResolver().getUniqueUser(uniqueUserId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to retrieve unique user - %s.",
                    uniqueUserId), e);
        }

        if (uniqueUser == null) {
            throw new UserNotFoundException("Invalid unique user id.");
        }

        Map<String, String> existingConnectorIdToConnectorUserIdMap = new HashMap<>();

        if (!uniqueUser.getUserPartitions().isEmpty()) {
            existingConnectorIdToConnectorUserIdMap.putAll(uniqueUser.getUserPartitions().stream()
                    .filter(UserPartition::isIdentityStore)
                    .collect(Collectors.toMap(UserPartition::getConnectorId, UserPartition::getConnectorUserId)));
        }

        Map<String, String> updatedUniqueIds = new HashMap<>();

        if ((claims == null || claims.isEmpty()) && !existingConnectorIdToConnectorUserIdMap.isEmpty()) {
            for (Map.Entry<String, String> entry : existingConnectorIdToConnectorUserIdMap.entrySet()) {
                String updatedConnectorUserId;
                try {
                    updatedConnectorUserId = domain.getIdentityStoreConnectorFromId(entry.getKey())
                            .updateUserAttributes(entry.getValue(), new ArrayList<>());
                } catch (IdentityStoreConnectorException e) {
                    throw new IdentityStoreServerException("Failed to update connector user id", e);
                }
                updatedUniqueIds.put(entry.getKey(), updatedConnectorUserId);
            }
        } else {
            List<MetaClaimMapping> metaClaimMappings;
            try {
                metaClaimMappings = domain.getMetaClaimMappings();
            } catch (DomainException e) {
                throw new IdentityStoreServerException("Failed to retrieve meta claim mappings.");
            }

            Map<String, List<Attribute>> connectorIdToAttributesMap = getConnectorIdToAttributesMap(claims,
                    metaClaimMappings);

            Map<String, String> connectorIdToConnectorUserIdMap = connectorIdToAttributesMap.keySet().stream()
                    .collect(Collectors.toMap(connectorId -> connectorId, connectorId -> ""));

            connectorIdToConnectorUserIdMap.putAll(existingConnectorIdToConnectorUserIdMap);

            for (Map.Entry<String, String> entry : connectorIdToConnectorUserIdMap.entrySet()) {

                String updatedConnectorUserId;
                if (isNullOrEmpty(entry.getValue())) {
                    try {
                        updatedConnectorUserId = domain.getIdentityStoreConnectorFromId(entry.getKey())
                                .addUser(connectorIdToAttributesMap.get(entry.getKey()));
                    } catch (IdentityStoreConnectorException e) {
                        throw new IdentityStoreServerException("Identity store connector failed to add user " +
                                "attributes.", e);
                    }
                } else {
                    try {
                        updatedConnectorUserId = domain.getIdentityStoreConnectorFromId(entry.getKey())
                                .updateUserAttributes(entry.getValue(), connectorIdToAttributesMap.get(entry.getKey()));
                    } catch (IdentityStoreConnectorException e) {
                        throw new IdentityStoreServerException("Failed to update user attributes.", e);
                    }
                }
                updatedUniqueIds.put(entry.getKey(), updatedConnectorUserId);
            }
        }

        if (!existingConnectorIdToConnectorUserIdMap.equals(updatedUniqueIds)) {
            try {
                domain.getUniqueIdResolver().updateUser(uniqueUserId, updatedUniqueIds);
            } catch (UniqueIdResolverException e) {
                throw new IdentityStoreServerException("Failed to update user connector ids.", e);
            }
        }
    }


    private void doUpdateUserClaims(String uniqueUserId, List<Claim> claimsToUpdate, List<Claim> claimsToRemove,
                                    Domain domain) throws IdentityStoreException, UserNotFoundException {

        UniqueUser uniqueUser;
        try {
            uniqueUser = domain.getUniqueIdResolver().getUniqueUser(uniqueUserId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to retrieve unique user - %s.",
                    uniqueUserId), e);
        }

        if (uniqueUser == null) {
            throw new UserNotFoundException("Invalid unique user id.");
        }

        Map<String, String> existingConnectorIdToConnectorUserIdMap = new HashMap<>();

        if (!uniqueUser.getUserPartitions().isEmpty()) {
            existingConnectorIdToConnectorUserIdMap.putAll(uniqueUser.getUserPartitions().stream()
                    .filter(UserPartition::isIdentityStore)
                    .collect(Collectors.toMap(UserPartition::getConnectorId, UserPartition::getConnectorUserId)));
        }

        List<MetaClaimMapping> metaClaimMappings;
        try {
            metaClaimMappings = domain.getMetaClaimMappings();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve meta claim mappings.");
        }


        Map<String, List<Attribute>> connectorAttributeMapToUpdate = getConnectorIdToAttributesMap(claimsToUpdate,
                metaClaimMappings);

        Map<String, List<Attribute>> connectorAttributeMapToRemove = getConnectorIdToAttributesMap(claimsToRemove,
                metaClaimMappings);

        Set<String> connectorIds = new HashSet<>();

        if (!connectorAttributeMapToUpdate.isEmpty()) {
            connectorIds.addAll(connectorAttributeMapToUpdate.keySet());
        }

        if (!connectorAttributeMapToRemove.isEmpty()) {
            connectorIds.addAll(connectorAttributeMapToRemove.keySet());
        }

        Map<String, String> updatedUniqueIds = new HashMap<>();

        for (String connectorId : connectorIds) {
            String updatedConnectorUserId;
            if (isNullOrEmpty(existingConnectorIdToConnectorUserIdMap.get(connectorId))) {
                if (connectorAttributeMapToUpdate.get(connectorId) != null) {
                    try {
                        updatedConnectorUserId = domain.getIdentityStoreConnectorFromId(connectorId)
                                .addUser(connectorAttributeMapToUpdate.get(connectorId));
                    } catch (IdentityStoreConnectorException e) {
                        throw new IdentityStoreServerException("Identity store connector failed to add user " +
                                "attributes.", e);
                    }
                    updatedUniqueIds.put(connectorId, updatedConnectorUserId);
                }
            } else {
                try {
                    updatedConnectorUserId = domain.getIdentityStoreConnectorFromId(connectorId)
                            .updateUserAttributes(
                                    existingConnectorIdToConnectorUserIdMap.get(connectorId),
                                    connectorAttributeMapToUpdate.get(connectorId),
                                    connectorAttributeMapToRemove.get(connectorId));
                } catch (IdentityStoreConnectorException e) {
                    throw new IdentityStoreServerException("Failed to update user attributes", e);
                }
                updatedUniqueIds.put(connectorId, updatedConnectorUserId);
            }

        }

        if (!existingConnectorIdToConnectorUserIdMap.equals(updatedUniqueIds)) {
            try {
                domain.getUniqueIdResolver().updateUser(uniqueUserId, updatedUniqueIds);
            } catch (UniqueIdResolverException e) {
                throw new IdentityStoreServerException("Failed to update user connector ids.", e);
            }
        }
    }

    private void doDeleteUser(String uniqueUserId, Domain domain) throws IdentityStoreException, UserNotFoundException {

        UniqueUser uniqueUser;
        try {
            uniqueUser = domain.getUniqueIdResolver().getUniqueUser(uniqueUserId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to retrieve unique user - %s.",
                    uniqueUserId), e);
        }

        if (uniqueUser == null) {
            throw new UserNotFoundException("Invalid unique user id.");
        }

        List<UserPartition> userPartitions = uniqueUser.getUserPartitions();

        if (!userPartitions.isEmpty()) {
            for (UserPartition userPartition : userPartitions) {
                if (userPartition.isIdentityStore()) {
                    try {
                        domain.getIdentityStoreConnectorFromId(userPartition.getConnectorId())
                                .deleteUser(userPartition.getConnectorUserId());
                    } catch (IdentityStoreConnectorException e) {
                        throw new IdentityStoreServerException("Failed to delete user", e);
                    }
                } else {
                    try {
                        domain.getCredentialStoreConnectorFromId(userPartition.getConnectorId())
                                .deleteCredential(userPartition.getConnectorUserId());
                    } catch (CredentialStoreConnectorException e) {
                        throw new IdentityStoreServerException(String.format("Failed to delete credential entry in " +
                                "connector - %s with id - %s", userPartition.getConnectorId(), userPartition
                                .getConnectorUserId()));
                    }
                }
            }
        }

        try {
            domain.getUniqueIdResolver().deleteUser(uniqueUserId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreException(String.format("Failed to delete unique user id - %s.", uniqueUserId));
        }
    }

    private Group doAddGroup(GroupDTO groupModel, Domain domain) throws IdentityStoreException {

        List<MetaClaimMapping> metaClaimMappings;
        try {
            metaClaimMappings = domain.getMetaClaimMappings();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve meta claim mappings.");
        }

        Map<String, List<Attribute>> connectorIdToAttributesMap = getConnectorIdToAttributesMap(groupModel
                .getClaims(), metaClaimMappings);

        List<GroupPartition> groupPartitions = new ArrayList<>();

        for (Map.Entry<String, List<Attribute>> entry : connectorIdToAttributesMap.entrySet()) {
            String connectorGroupId;
            try {
                connectorGroupId = domain.getIdentityStoreConnectorFromId(entry.getKey()).addGroup(entry.getValue());
            } catch (IdentityStoreConnectorException e) {
                // Recover from the inconsistent state in the connectors
                if (groupPartitions.size() > 0) {
                    removeAddedGroupsInAFailure(domain, groupPartitions);
                }
                throw new IdentityStoreServerException("Identity store connector failed to add user attributes.",
                        e);
            }

            groupPartitions.add(new GroupPartition(entry.getKey(), connectorGroupId));
        }


        String groupUniqueId = IdentityUserMgtUtil.generateUUID();
        try {
            domain.getUniqueIdResolver().addGroup(new UniqueGroup(groupUniqueId, groupPartitions), domain
                    .getDomainName());
        } catch (UniqueIdResolverException e) {
            // Recover from the inconsistent state in the connectors
            removeAddedGroupsInAFailure(domain, groupPartitions);

            throw new IdentityStoreServerException("Error occurred while persisting user unique id.", e);
        }

        return new Group.GroupBuilder()
                .setGroupId(groupUniqueId)
                .setDomainName(domain.getDomainName())
                .setIdentityStore(this)
                .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                .build();
    }

    private List<Group> doAddGroups(List<GroupDTO> groupModels, Domain domain) throws IdentityStoreException {

        List<MetaClaimMapping> metaClaimMappings;
        try {
            metaClaimMappings = domain.getMetaClaimMappings();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve meta claim mappings.");
        }

        Map<String, GroupDTO> uniqueGroupIdToGroupModelMap = groupModels.stream()
                .filter(Objects::nonNull)
                .filter(groupModel -> !groupModel.getClaims().isEmpty())
                .collect(Collectors.toMap(groupModel -> IdentityUserMgtUtil.generateUUID(), groupModel -> groupModel));

        Map<String, Map<String, List<Attribute>>> connectorIdToUniqueGroupIdToAttributesMap = new HashMap<>();

        uniqueGroupIdToGroupModelMap.entrySet().stream()
                .filter(Objects::nonNull)
                .forEach(groupModelEntry -> {

                    Map<String, List<Attribute>> connectorIdToAttributesMap = getConnectorIdToAttributesMap
                            (groupModelEntry.getValue().getClaims(), metaClaimMappings);

                    if (!connectorIdToAttributesMap.isEmpty()) {
                        connectorIdToAttributesMap.entrySet().stream()
                                .forEach(attributeEntry -> {
                                            Map<String, List<Attribute>> uniqueGroupIdToAttributesMap =
                                                    connectorIdToUniqueGroupIdToAttributesMap.get(attributeEntry
                                                            .getKey());
                                            if (uniqueGroupIdToAttributesMap == null) {
                                                uniqueGroupIdToAttributesMap = new HashMap<>();
                                                connectorIdToUniqueGroupIdToAttributesMap.put(attributeEntry.getKey(),
                                                        uniqueGroupIdToAttributesMap);
                                            }
                                            uniqueGroupIdToAttributesMap.put(groupModelEntry.getKey(), attributeEntry
                                                    .getValue());
                                        }
                                );
                    }
                });

        Map<String, List<GroupPartition>> uniqueGroupIdToGroupPartitionsMap = new HashMap<>();
        if (!connectorIdToUniqueGroupIdToAttributesMap.isEmpty()) {
            for (Map.Entry<String, Map<String, List<Attribute>>> entry : connectorIdToUniqueGroupIdToAttributesMap
                    .entrySet()) {

                Map<String, String> uniqueGroupIds;
                try {
                    uniqueGroupIds = domain.getIdentityStoreConnectorFromId(entry.getKey()).addGroups(entry.getValue());
                } catch (IdentityStoreConnectorException e) {
                    if (!uniqueGroupIdToGroupPartitionsMap.isEmpty()) {
                        uniqueGroupIdToGroupPartitionsMap.entrySet().stream()
                                .forEach(partitionEntry -> removeAddedGroupsInAFailure(domain,
                                        partitionEntry.getValue()));
                    }
                    throw new IdentityStoreServerException("Failed to add groups.", e);
                }
                if (uniqueGroupIds != null) {
                    uniqueGroupIds.entrySet().stream()
                            .forEach(uniqueGroupId -> {
                                List<GroupPartition> groupPartitions = uniqueGroupIdToGroupPartitionsMap
                                        .get(uniqueGroupId.getKey());
                                if (groupPartitions == null) {
                                    groupPartitions = new ArrayList<>();
                                    uniqueGroupIdToGroupPartitionsMap.put(uniqueGroupId.getKey(), groupPartitions);
                                }
                                groupPartitions.add(new GroupPartition(entry.getKey(), uniqueGroupId.getValue()));
                            });
                }
            }
        }

        List<UniqueGroup> uniqueGroups = uniqueGroupIdToGroupPartitionsMap.entrySet().stream()
                .map(entry -> new UniqueGroup(entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());

        try {
            domain.getUniqueIdResolver().addGroups(uniqueGroups, domain.getDomainName());
        } catch (UniqueIdResolverException e) {
            if (!uniqueGroupIdToGroupPartitionsMap.isEmpty()) {
                uniqueGroupIdToGroupPartitionsMap.entrySet().stream()
                        .forEach(partitionEntry -> removeAddedGroupsInAFailure(domain, partitionEntry.getValue()));
            }
            throw new IdentityStoreServerException("Error occurred while persisting group unique ids.", e);
        }

        return uniqueGroups.stream()
                .map(uniqueGroup -> new Group.GroupBuilder()
                        .setGroupId(uniqueGroup.getUniqueGroupId())
                        .setDomainName(domain.getDomainName())
                        .setIdentityStore(this)
                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    private void doUpdateGroupClaims(String uniqueGroupId, List<Claim> claims, Domain domain) throws
            IdentityStoreException, GroupNotFoundException {

        UniqueGroup uniqueGroup;
        try {
            uniqueGroup = domain.getUniqueIdResolver().getUniqueGroup(uniqueGroupId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to retrieve unique group - %s.",
                    uniqueGroupId), e);
        }

        if (uniqueGroup == null) {
            throw new GroupNotFoundException("Invalid unique group id.");
        }

        Map<String, String> existingConnectorIdToConnectorGroupIdMap = new HashMap<>();

        if (!uniqueGroup.getGroupPartitions().isEmpty()) {
            existingConnectorIdToConnectorGroupIdMap.putAll(uniqueGroup.getGroupPartitions().stream()
                    .collect(Collectors.toMap(GroupPartition::getConnectorId, GroupPartition::getConnectorGroupId)));
        }

        Map<String, String> updatedUniqueIds = new HashMap<>();

        if ((claims == null || claims.isEmpty()) && !existingConnectorIdToConnectorGroupIdMap.isEmpty()) {
            for (Map.Entry<String, String> entry : existingConnectorIdToConnectorGroupIdMap.entrySet()) {
                String updatedConnectorGroupId;
                try {
                    updatedConnectorGroupId = domain.getIdentityStoreConnectorFromId(entry.getKey())
                            .updateGroupAttributes(entry.getValue(), new ArrayList<>());
                } catch (IdentityStoreConnectorException e) {
                    throw new IdentityStoreServerException("Failed to update group attributes.", e);
                }
                updatedUniqueIds.put(entry.getKey(), updatedConnectorGroupId);
            }
        } else {
            List<MetaClaimMapping> metaClaimMappings;
            try {
                metaClaimMappings = domain.getMetaClaimMappings();
            } catch (DomainException e) {
                throw new IdentityStoreServerException("Failed to retrieve meta claim mappings.");
            }

            Map<String, List<Attribute>> connectorIdToAttributesMap = getConnectorIdToAttributesMap(claims,
                    metaClaimMappings);

            Map<String, String> connectorIdToConnectorGroupIdMap = connectorIdToAttributesMap.keySet().stream()
                    .collect(Collectors.toMap(connectorId -> connectorId, connectorId -> ""));

            connectorIdToConnectorGroupIdMap.putAll(existingConnectorIdToConnectorGroupIdMap);

            for (Map.Entry<String, String> entry : connectorIdToConnectorGroupIdMap.entrySet()) {

                String updatedConnectorGroupId;
                if (isNullOrEmpty(entry.getValue())) {
                    try {
                        updatedConnectorGroupId = domain.getIdentityStoreConnectorFromId(entry.getKey())
                                .addGroup(connectorIdToAttributesMap.get(entry.getKey()));
                    } catch (IdentityStoreConnectorException e) {
                        throw new IdentityStoreServerException("Identity store connector failed to add group " +
                                "attributes.", e);
                    }
                } else {
                    try {
                        updatedConnectorGroupId = domain.getIdentityStoreConnectorFromId(entry.getKey())
                                .updateGroupAttributes(entry.getValue(),
                                        connectorIdToAttributesMap.get(entry.getKey()));
                    } catch (IdentityStoreConnectorException e) {
                        throw new IdentityStoreServerException("Failed to update group attributes.", e);
                    }
                }
                updatedUniqueIds.put(entry.getKey(), updatedConnectorGroupId);
            }
        }

        if (!existingConnectorIdToConnectorGroupIdMap.equals(updatedUniqueIds)) {
            try {
                domain.getUniqueIdResolver().updateGroup(uniqueGroupId, updatedUniqueIds);
            } catch (UniqueIdResolverException e) {
                throw new IdentityStoreServerException("Failed to update group connector ids.", e);
            }
        }
    }

    private void doUpdateGroupClaims(String uniqueGroupId, List<Claim> claimsToUpdate, List<Claim> claimsToRemove,
                                     Domain domain) throws IdentityStoreException, GroupNotFoundException {

        UniqueGroup uniqueGroup;
        try {
            uniqueGroup = domain.getUniqueIdResolver().getUniqueGroup(uniqueGroupId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to retrieve unique group - %s.",
                    uniqueGroupId), e);
        }

        if (uniqueGroup == null) {
            throw new GroupNotFoundException("Invalid unique group id.");
        }

        Map<String, String> existingConnectorIdToConnectorGroupIdMap = new HashMap<>();

        if (!uniqueGroup.getGroupPartitions().isEmpty()) {
            existingConnectorIdToConnectorGroupIdMap.putAll(uniqueGroup.getGroupPartitions().stream()
                    .collect(Collectors.toMap(GroupPartition::getConnectorId, GroupPartition::getConnectorGroupId)));
        }

        List<MetaClaimMapping> metaClaimMappings;
        try {
            metaClaimMappings = domain.getMetaClaimMappings();
        } catch (DomainException e) {
            throw new IdentityStoreServerException("Failed to retrieve meta claim mappings.");
        }


        Map<String, List<Attribute>> connectorAttributeMapToUpdate = getConnectorIdToAttributesMap(claimsToUpdate,
                metaClaimMappings);

        Map<String, List<Attribute>> connectorAttributeMapToRemove = getConnectorIdToAttributesMap(claimsToRemove,
                metaClaimMappings);

        Set<String> connectorIds = new HashSet<>();

        if (!connectorAttributeMapToUpdate.isEmpty()) {
            connectorIds.addAll(connectorAttributeMapToUpdate.keySet());
        }

        if (!connectorAttributeMapToRemove.isEmpty()) {
            connectorIds.addAll(connectorAttributeMapToRemove.keySet());
        }

        Map<String, String> updatedUniqueIds = new HashMap<>();

        for (String connectorId : connectorIds) {
            String updatedConnectorGroupId;
            if (isNullOrEmpty(existingConnectorIdToConnectorGroupIdMap.get(connectorId))) {
                if (connectorAttributeMapToUpdate.get(connectorId) != null) {
                    try {
                        updatedConnectorGroupId = domain.getIdentityStoreConnectorFromId(connectorId)
                                .addGroup(connectorAttributeMapToUpdate.get(connectorId));
                    } catch (IdentityStoreConnectorException e) {
                        throw new IdentityStoreServerException("Identity store connector failed to add group " +
                                "attributes.", e);
                    }
                    updatedUniqueIds.put(connectorId, updatedConnectorGroupId);
                }
            } else {
                try {
                    updatedConnectorGroupId = domain.getIdentityStoreConnectorFromId(connectorId)
                            .updateGroupAttributes(
                                    existingConnectorIdToConnectorGroupIdMap.get(connectorId),
                                    connectorAttributeMapToUpdate.get(connectorId),
                                    connectorAttributeMapToRemove.get(connectorId));
                } catch (IdentityStoreConnectorException e) {
                    throw new IdentityStoreServerException("Failed to update group attributes.", e);
                }
                updatedUniqueIds.put(connectorId, updatedConnectorGroupId);
            }

        }

        if (!existingConnectorIdToConnectorGroupIdMap.equals(updatedUniqueIds)) {
            try {
                domain.getUniqueIdResolver().updateGroup(uniqueGroupId, updatedUniqueIds);
            } catch (UniqueIdResolverException e) {
                throw new IdentityStoreServerException("Failed to update group connector ids.", e);
            }
        }
    }


    private void doDeleteGroup(String uniqueGroupId, Domain domain) throws IdentityStoreException,
            GroupNotFoundException {

        UniqueGroup uniqueGroup;
        try {
            uniqueGroup = domain.getUniqueIdResolver().getUniqueGroup(uniqueGroupId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreServerException(String.format("Failed to retrieve unique group - %s.",
                    uniqueGroupId), e);
        }

        if (uniqueGroup == null) {
            throw new GroupNotFoundException("Invalid unique group id.");
        }

        List<GroupPartition> groupPartitions = uniqueGroup.getGroupPartitions();

        if (!groupPartitions.isEmpty()) {
            for (GroupPartition groupPartition : groupPartitions) {
                try {
                    domain.getIdentityStoreConnectorFromId(groupPartition.getConnectorId())
                            .deleteGroup(groupPartition.getConnectorGroupId());
                } catch (IdentityStoreConnectorException e) {
                    throw new IdentityStoreServerException(String.format("Failed to delete user entry in " +
                            "connector - %s with id - %s", groupPartition.getConnectorId(), groupPartition
                            .getConnectorGroupId()));
                }
            }
        }

        try {
            domain.getUniqueIdResolver().deleteGroup(uniqueGroupId);
        } catch (UniqueIdResolverException e) {
            throw new IdentityStoreException(String.format("Failed to delete unique user id - %s.", uniqueGroupId));
        }
    }

    private AuthenticationContext doAuthenticate(Claim claim, Callback[] credentials, Domain domain)
            throws AuthenticationFailure {

        MetaClaimMapping metaClaimMapping;
        try {
            metaClaimMapping = domain.getMetaClaimMapping(claim.getClaimUri());
        } catch (DomainException e) {
            throw new AuthenticationFailure("Failed to retrieve the meta claim mapping for the claim URI.", e);
        }

        String connectorUserId;
        try {
            connectorUserId = domain.getIdentityStoreConnectorFromId(metaClaimMapping.getIdentityStoreConnectorId())
                    .getConnectorUserId(metaClaimMapping.getAttributeName(), claim.getValue());
        } catch (UserNotFoundException | IdentityStoreConnectorException e) {
            throw new AuthenticationFailure("Invalid claim value. No user mapped to the provided claim.", e);
        }

        UniqueUser uniqueUser;
        try {
            uniqueUser = domain.getUniqueIdResolver().getUniqueUserFromConnectorUserId(connectorUserId, metaClaimMapping
                    .getIdentityStoreConnectorId());
        } catch (UniqueIdResolverException e) {
            throw new AuthenticationFailure("Failed retrieve unique user info.", e);
        }

        for (UserPartition userPartition : uniqueUser.getUserPartitions()) {
            if (!userPartition.isIdentityStore()) {
                CredentialStoreConnector connector = domain.getCredentialStoreConnectorFromId(userPartition
                        .getConnectorId());
                if (connector.canHandle(credentials)) {
                    try {
                        connector.authenticate(userPartition.getConnectorUserId(), credentials);

                        return new AuthenticationContext(
                                new User.UserBuilder()
                                        .setUserId(uniqueUser.getUniqueUserId())
                                        .setIdentityStore(this)
                                        .setAuthorizationStore(IdentityMgtDataHolder.getInstance()
                                                .getAuthorizationStore())
                                        .setDomainName(domain.getDomainName())
                                        .build());
                    } catch (CredentialStoreConnectorException e) {
                        throw new AuthenticationFailure("Failed to authenticate from the provided credential.", e);
                    }
                }
            }
        }

        throw new AuthenticationFailure("Failed to authenticate user.");
    }

    private Domain getPrimaryDomain() throws DomainException {

        Domain domain = sortedDomains.first();

        if (domain == null) {
            throw new DomainException("No domains registered.");
        }

        return domain;
    }

    private Domain getDomainFromDomainName(String domainName) throws DomainException {

        Domain domain = domainNameToDomainMap.get(domainName);

        if (domain == null) {
            throw new DomainException(String.format("Domain %s was not found", domainName));
        }

        return domain;
    }

    private Map<String, List<Attribute>> getConnectorIdToAttributesMap(List<Claim> claims,
                                                                       List<MetaClaimMapping> metaClaimMappings) {

        Map<String, List<Attribute>> connectorIdToAttributesMap = new HashMap<>();

        if (claims != null && !claims.isEmpty()) {
            claims.stream()
                    .forEach(claim -> {
                                Optional<MetaClaimMapping> optional = metaClaimMappings.stream()
                                        .filter(metaClaimMapping -> metaClaimMapping.getMetaClaim().getClaimUri()
                                                .equals(claim.getClaimUri()))
                                        .findFirst();

                                if (optional.isPresent()) {
                                    MetaClaimMapping metaClaimMapping = optional.get();
                                    List<Attribute> attributes = connectorIdToAttributesMap.get(metaClaimMapping
                                            .getIdentityStoreConnectorId());
                                    if (attributes == null) {
                                        attributes = new ArrayList<>();
                                        connectorIdToAttributesMap.put(metaClaimMapping.getIdentityStoreConnectorId(),
                                                attributes);
                                    }
                                    attributes.add(new Attribute(metaClaimMapping.getAttributeName(),
                                            claim.getValue()));
                                }
                            }
                    );
        }

        return connectorIdToAttributesMap;
    }

    private List<Claim> buildClaims(List<MetaClaimMapping> metaClaimMappings, Map<String, List<Attribute>>
            connectorIdToAttributesMap) {

        List<Claim> claims = new ArrayList<>();

        if (!connectorIdToAttributesMap.isEmpty()) {
            connectorIdToAttributesMap.entrySet().stream()
                    .filter(entry -> entry.getValue() != null && !entry.getValue().isEmpty())
                    .forEach(entry -> {
                                entry.getValue().stream()
                                        .forEach(attribute -> {
                                                    Optional<MetaClaim> optional = metaClaimMappings.stream()
                                                            .filter(metaClaimMapping -> metaClaimMapping
                                                                    .getAttributeName().equals(attribute
                                                                            .getAttributeName()))
                                                            .map(MetaClaimMapping::getMetaClaim)
                                                            .findAny();

                                                    if (optional.isPresent()) {
                                                        MetaClaim metaClaim = optional.get();
                                                        claims.add(new Claim(metaClaim.getDialectUri(), metaClaim
                                                                .getClaimUri(), attribute.getAttributeValue()));
                                                    }
                                                }
                                        );
                            }
                    );
        }

        return claims;
    }

    private Map<String, List<Callback>> getConnectorIdToCredentialsMap(
            List<Callback> credentials, List<CredentialStoreConnector> credentialStoreConnectors) {

        Map<String, List<Callback>> connectorIdToCredentialsMap = new HashMap<>();

        if (!credentials.isEmpty()) {
            credentials.stream()
                    .filter(Objects::nonNull)
                    .forEach(callback -> {
                        Optional<CredentialStoreConnector> optional = credentialStoreConnectors.stream()
                                .filter(connector -> connector.canStore(new Callback[]{callback}))
                                .findAny();

                        if (optional.isPresent()) {
                            CredentialStoreConnector connector = optional.get();
                            List<Callback> callbacks = connectorIdToCredentialsMap.get(connector
                                    .getCredentialStoreConnectorId());
                            if (callbacks == null) {
                                callbacks = new ArrayList<>();
                                connectorIdToCredentialsMap.put(connector.getCredentialStoreConnectorId(), callbacks);
                            }
                            callbacks.add(callback);
                        }
                    });
        }

        return connectorIdToCredentialsMap;
    }

    private Map<String, List<String>> getConnectorIdToAttributeNameMap(List<MetaClaimMapping> metaClaimMappings,
                                                                       List<MetaClaim> metaClaims) {

        Map<String, List<String>> connectorIdToAttributeNameMap = new HashMap<>();

        if (!metaClaims.isEmpty()) {
            metaClaims.stream()
                    .filter(Objects::nonNull)
                    .filter(metaClaim -> !isNullOrEmpty(metaClaim.getClaimUri()))
                    .forEach(metaClaim -> {
                                Optional<MetaClaimMapping> optional = metaClaimMappings.stream()
                                        .filter(metaClaimMapping -> metaClaimMapping.getMetaClaim().getClaimUri()
                                                .equals(metaClaim.getClaimUri()))
                                        .findFirst();
                                if (optional.isPresent()) {
                                    MetaClaimMapping metaClaimMapping = optional.get();

                                    List<String> attributeNames = connectorIdToAttributeNameMap.get(metaClaimMapping
                                            .getIdentityStoreConnectorId());
                                    if (attributeNames == null) {
                                        attributeNames = new ArrayList<String>();
                                        connectorIdToAttributeNameMap.put(metaClaimMapping
                                                .getIdentityStoreConnectorId(), attributeNames);
                                    }
                                    attributeNames.add(metaClaimMapping.getAttributeName());
                                }
                            }
                    );
        }
        return connectorIdToAttributeNameMap;
    }

    private void removeAddedUsersInAFailure(Domain domain, List<UserPartition> userPartitions) {

        for (UserPartition userPartition : userPartitions) {
            try {
                domain.getIdentityStoreConnectorFromId(userPartition.getConnectorId())
                        .removeAddedUsersInAFailure(Collections.singletonList(userPartition
                                .getConnectorUserId()));
            } catch (IdentityStoreConnectorException e) {
                log.error("Error occurred while removing invalid connector user ids. " + String.join(" , ",
                        userPartitions.stream().map(UserPartition::toString).collect(Collectors.toList())
                ), e);
            }
        }
    }

    private void removeAddedGroupsInAFailure(Domain domain, List<GroupPartition> groupPartitions) {

        for (GroupPartition groupPartition : groupPartitions) {
            try {
                domain.getIdentityStoreConnectorFromId(groupPartition.getConnectorId())
                        .removeAddedGroupsInAFailure(Collections.singletonList(groupPartition
                                .getConnectorGroupId()));
            } catch (IdentityStoreConnectorException e) {
                log.error("Error occurred while removing invalid connector user ids. " + String.join(" , ",
                        groupPartitions.stream().map(GroupPartition::toString).collect(Collectors.toList())
                ), e);
            }
        }
    }
}

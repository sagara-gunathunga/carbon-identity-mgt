package org.wso2.carbon.identity.mgt.impl.user.impl;

import org.wso2.carbon.identity.mgt.impl.user.UniqueIdResolver;
import org.wso2.carbon.identity.mgt.impl.user.UniqueIdResolverFactory;

/**
 * JDBC Unique Id Resolver Factory.
 */
public class JDBCUniqueIdResolverFactory implements UniqueIdResolverFactory {

    @Override
    public UniqueIdResolver getInstance() {
        return new JDBCUniqueIdResolver();
    }
}

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.main.test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * A wrapper class for the authentication provider; Will do something more for Kylin.
 */
public class KylinAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(KylinAuthenticationProvider.class);

    //Embedded authentication provider
    private AuthenticationProvider authenticationProvider;

    public KylinAuthenticationProvider(AuthenticationProvider authenticationProvider) {
        super();
        Assert.notNull(authenticationProvider, "The embedded authenticationProvider should not be null.");
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication authed = null;
        logger.info("authentication.getName():{}", authentication.getName());
        logger.info("authentication.getCredentials():{}", authentication.getCredentials());
        logger.info("authentication.getClass().getName():{}", authentication.getClass().getName());
        
        try {
            if(logger.isDebugEnabled()){
                logger.debug("Authentication attempt using " + authenticationProvider.getClass().getName());
            }
            logger.info("authenticationProvider.getClass().getName():{}", authenticationProvider.getClass().getName());
            authed = authenticationProvider.authenticate(authentication);
            logger.info("authed.getPrincipal():{}", authed.getPrincipal().toString());
            logger.info("authed.getCredentials():{}", authed.getCredentials().toString());
        } catch (AuthenticationException e) {
            logger.error("Failed to auth user: " + authentication.getName(), e);
            throw e;
        } catch (Exception e) {
            logger.error("Failed to auth user: " + authentication.getName(), e);
            throw e;
        }

        logger.debug("Authenticated user " + authed.toString());

        UserDetails user;

        if (authed.getDetails() == null) {
            //authed.setAuthenticated(false);
            throw new UsernameNotFoundException("User not found in LDAP, check whether he/she has been added to the groups.");
        }

        if (authed.getDetails() instanceof UserDetails) {
            user = (UserDetails) authed.getDetails();
        } else {
            user = new User(authentication.getName(), "skippped-ldap", authed.getAuthorities());
        }
        Assert.notNull(user, "The UserDetail is null.");
        return authed;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authenticationProvider.supports(authentication);
    }

    public AuthenticationProvider getAuthenticationProvider() {
        return authenticationProvider;
    }

    public void setAuthenticationProvider(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

}

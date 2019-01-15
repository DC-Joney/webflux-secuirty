package com.secuirty.starter.security.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;

public class QueryAccessToken extends AbstractAuthenticationToken {

    private BearerTokenAuthenticationToken authenticationToken;

     QueryAccessToken(BearerTokenAuthenticationToken authenticationToken) {
        super(Collections.emptyList());

        Assert.hasText(authenticationToken.getToken(), "token cannot be empty");

        this.authenticationToken = authenticationToken;
    }


     String getToken() {
        return this.authenticationToken.getToken();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getCredentials() {
        return this.getToken();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getPrincipal() {
        return this.getToken();
    }
}

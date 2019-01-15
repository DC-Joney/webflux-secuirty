package com.secuirty.starter.security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.server.ServerBearerTokenAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class QueryTokenAuthenticationConverter extends ServerBearerTokenAuthenticationConverter {

    public QueryTokenAuthenticationConverter(){
        setAllowUriQueryParameter(true);
    }

    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return super.convert(exchange)
                .checkpoint()
                .filter(token-> token instanceof BearerTokenAuthenticationToken)
                .cast(BearerTokenAuthenticationToken.class)
                .map(QueryAccessToken::new);
    }


}

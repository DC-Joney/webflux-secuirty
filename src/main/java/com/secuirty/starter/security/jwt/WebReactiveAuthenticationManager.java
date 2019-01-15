package com.secuirty.starter.security.jwt;

import lombok.extern.log4j.Log4j2;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;
import reactor.core.publisher.SynchronousSink;

@Log4j2
public class WebReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    private Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter
            = new ReactiveJwtAuthenticationConverterAdapter(new JwtAuthenticationConverter());

    private final ReactiveJwtDecoder jwtDecoder;

    public WebReactiveAuthenticationManager(ReactiveJwtDecoder jwtDecoder) {
        Assert.notNull(jwtDecoder, "jwtDecoder cannot be null");
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.justOrEmpty(authentication)
                .filter(a -> a instanceof QueryAccessToken)
                .cast(QueryAccessToken.class)
                .map(QueryAccessToken::getToken)
                .flatMap(this.jwtDecoder::decode)
                .checkpoint("valid token")
                .flatMap(this.jwtAuthenticationConverter::convert)
                .filter(token-> token instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .handle(this::repackageToken)
                .cast(Authentication.class)
                .onErrorMap(JwtException.class, this::onError);
    }

    private  void repackageToken(JwtAuthenticationToken token, SynchronousSink<AbstractAuthenticationToken> synchronousSink) {
        String authorities = (String) token.getToken()
                .getClaims().getOrDefault("authorities", "ROLE_ANONYMOUS");

        AbstractAuthenticationToken authenticationToken
                = new JwtAuthenticationToken(token.getToken(),AuthorityUtils.createAuthorityList(authorities.split(",")));

        synchronousSink.next(authenticationToken);
    }



    public void setJwtAuthenticationConverter(
            Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter) {

        Assert.notNull(jwtAuthenticationConverter, "jwtAuthenticationConverter cannot be null");
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
    }

    private OAuth2AuthenticationException onError(JwtException e) {
        OAuth2Error invalidRequest = invalidToken(e.getMessage());
        return new OAuth2AuthenticationException(invalidRequest, e.getMessage());
    }

    private static OAuth2Error invalidToken(String message) {
        return new BearerTokenError(
                BearerTokenErrorCodes.INVALID_TOKEN,
                HttpStatus.UNAUTHORIZED,
                message,
                "https://tools.ietf.org/html/rfc6750#section-3.1");
    }
}

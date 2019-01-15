package com.secuirty.starter.security.config;

import com.secuirty.starter.security.jwt.QueryTokenAuthenticationConverter;
import com.secuirty.starter.security.jwt.WebReactiveAuthenticationManager;
import com.secuirty.starter.security.support.JsonServerAuthenticationFailureHandler;
import com.secuirty.starter.security.support.strategy.JsonStrategy;
import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult.match;
import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult.notMatch;

public class AuthenticationJwtSpec{


    private ApplicationContext context;
    private ReactiveAuthenticationManager authenticationManager;
    private ReactiveJwtDecoder jwtDecoder;
    private ServerAuthenticationFailureHandler failureHandler = new JsonServerAuthenticationFailureHandler(getBean(JsonStrategy.class));

    private Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter
            = new ReactiveJwtAuthenticationConverterAdapter(new JwtAuthenticationConverter());

//    private ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec.BearerTokenServerWebExchangeMatcher bearerTokenServerWebExchangeMatcher =
//            new ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec.BearerTokenServerWebExchangeMatcher();

    public AuthenticationJwtSpec(ApplicationContext context){
        this.context = context;
    }


    public AuthenticationJwtSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
        return this;
    }

    public AuthenticationJwtSpec jwtAuthenticationConverter
    (Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter) {
        Assert.notNull(jwtAuthenticationConverter, "jwtAuthenticationConverter cannot be null");
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
        return this;
    }

    public AuthenticationJwtSpec jwtDecoder(ReactiveJwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
        return this;
    }

    public AuthenticationJwtSpec failureHandler (ServerAuthenticationFailureHandler failureHandler){
        this.failureHandler = failureHandler;
        return this;
    }



    public AuthenticationJwtSpec publicKey(RSAPublicKey publicKey) {
        this.jwtDecoder = new NimbusReactiveJwtDecoder(publicKey);
        return this;
    }


    public AuthenticationJwtSpec jwkSetUri(String jwkSetUri) {
        this.jwtDecoder = new NimbusReactiveJwtDecoder(jwkSetUri);
        return this;
    }

    protected Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>
    getJwtAuthenticationConverter() {
        return this.jwtAuthenticationConverter;
    }


    protected ReactiveJwtDecoder getJwtDecoder() {
        if (this.jwtDecoder == null) {
            return getBean(ReactiveJwtDecoder.class);
        }
        return this.jwtDecoder;
    }

    private <T> T getBean(Class<T> beanClass) {
        if (this.context == null) {
            return null;
        }
        return this.context.getBean(beanClass);
    }


    public void configure(ServerHttpSecurity http) {
        QueryTokenAuthenticationConverter queryTokenAuthenticationConverter =
                new QueryTokenAuthenticationConverter();
        ReactiveAuthenticationManager authenticationManager = getAuthenticationManager();
        AuthenticationWebFilter jwt = new AuthenticationWebFilter(authenticationManager);
        jwt.setRequiresAuthenticationMatcher(new JwtTokenServerWebExchangeMatcher());
        jwt.setServerAuthenticationConverter(queryTokenAuthenticationConverter);
        jwt.setAuthenticationFailureHandler(this.failureHandler);
        http.addFilterAt(jwt, SecurityWebFiltersOrder.HTTP_BASIC);
    }




    private ReactiveAuthenticationManager getAuthenticationManager() {

        if (this.authenticationManager != null) {
            return this.authenticationManager;
        }

        ReactiveJwtDecoder jwtDecoder = getJwtDecoder();
        Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter =
                getJwtAuthenticationConverter();
        WebReactiveAuthenticationManager authenticationManager =
                new WebReactiveAuthenticationManager(jwtDecoder);
        authenticationManager.setJwtAuthenticationConverter(jwtAuthenticationConverter);

        return authenticationManager;
    }


    private class JwtTokenServerWebExchangeMatcher implements ServerWebExchangeMatcher {

        @Override
        public Mono<MatchResult> matches(ServerWebExchange exchange) {
            return Mono.justOrEmpty(exchange.getRequest().getQueryParams().containsKey("access_token"))
                    .filterWhen(bool -> {
                        if(bool){
                            List<String> strings = exchange.getRequest().getQueryParams().get("access_token");
                            return Mono.just(strings.size() > 0 && strings.get(0) != null && StringUtils.hasText(strings.get(0)));
                        }
                        return Mono.empty();
                    })
                    .switchIfEmpty(Mono.defer(()-> Mono.just(false)))
                    .flatMap(this::queryState);
        }

        private Mono<MatchResult> queryState(boolean bool) {
            return bool  ? match() : notMatch();
        }
    }

}

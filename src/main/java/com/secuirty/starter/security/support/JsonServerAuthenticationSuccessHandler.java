package com.secuirty.starter.security.support;

import com.secuirty.starter.security.support.strategy.DefaultJsonStrategy;
import com.secuirty.starter.security.support.strategy.JsonStrategy;
import com.secuirty.starter.security.support.utils.JsonConvertUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import reactor.core.publisher.Mono;

import java.util.Optional;

public class JsonServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

    private JsonStrategy jsonStrategy;
    private RSAKeyPair rsaKeyPair;

    public JsonServerAuthenticationSuccessHandler(JsonStrategy jsonStrategies, RSAKeyPair rsaKeyPair){
        this.jsonStrategy = Optional.ofNullable(jsonStrategies).orElseGet(DefaultJsonStrategy::new);
        this.rsaKeyPair = rsaKeyPair;
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        return Mono.fromCompletionStage(JsonConvertUtils.convertToJWtString(authentication,rsaKeyPair))
                .flatMap(authStr-> jsonStrategy.writeResponse(webFilterExchange.getExchange(),authStr));
    }

    public void setJsonStrategy(JsonStrategy jsonStrategy) {
        this.jsonStrategy = jsonStrategy;
    }
}

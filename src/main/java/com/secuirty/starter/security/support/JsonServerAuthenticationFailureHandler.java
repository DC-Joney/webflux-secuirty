package com.secuirty.starter.security.support;

import com.secuirty.starter.security.support.strategy.DefaultJsonStrategy;
import com.secuirty.starter.security.support.strategy.JsonStrategy;
import com.secuirty.starter.security.support.utils.JsonConvertUtils;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Log4j2
public class JsonServerAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {

    private JsonStrategy jsonStrategy;

    public JsonServerAuthenticationFailureHandler(JsonStrategy jsonStrategy){
        this.jsonStrategy = Optional.ofNullable(jsonStrategy).orElseGet(DefaultJsonStrategy::new);
    }

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException authenticationException) {
        return Mono.fromCompletionStage(JsonConvertUtils.convertToString(authenticationException))
                .flatMap(authStr-> jsonStrategy.writeResponse(webFilterExchange.getExchange(),authStr))
                .and(s -> {
                    log.info(authenticationException);
                    s.onComplete();
                })
                .subscriberContext(ReactiveSecurityContextHolder.clearContext());
    }


    public void setJsonStrategy(JsonStrategy jsonStrategy) {
        this.jsonStrategy = jsonStrategy;
    }
}

package com.secuirty.starter.security.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Log4j2
public class JwtHttpStatusServerEntryPoint extends HttpStatusServerEntryPoint {

    public JwtHttpStatusServerEntryPoint(HttpStatus httpStatus) {
        super(httpStatus);
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException authException) {
        return super.commence(exchange, authException)
                .doOnNext(log::info);
    }
}

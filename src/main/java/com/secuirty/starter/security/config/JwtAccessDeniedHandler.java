package com.secuirty.starter.security.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Log4j2
public class JwtAccessDeniedHandler extends HttpStatusServerAccessDeniedHandler {

    public JwtAccessDeniedHandler(HttpStatus httpStatus) {
        super(httpStatus);
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException e) {
        return Mono.justOrEmpty(e)
                .doOnNext(log::info)
                .then(super.handle(exchange,e))
                .doOnNext(log::info);
    }
}

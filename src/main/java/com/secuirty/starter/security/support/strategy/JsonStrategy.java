package com.secuirty.starter.security.support.strategy;

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@FunctionalInterface
public interface JsonStrategy {

    Mono<Void> writeResponse(ServerWebExchange serverWebExchange, String attrName);

}

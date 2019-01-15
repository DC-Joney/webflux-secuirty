package com.secuirty.starter.security.filter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

public class SecurityContextClearFilter implements WebFilter {

    private final ServerSecurityContextRepository repository;

    public SecurityContextClearFilter() {
        this.repository = new WebSessionServerSecurityContextRepository();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return Mono.subscriberContext()
                .flatMap(context-> clearContext(exchange,context))
                .then(chain.filter(exchange));
    }

    private Mono<Void> clearContext(ServerWebExchange exchange, Context context){
        return repository.load(exchange)
                .flatMap(securityContext -> {
                    if (securityContext != null && securityContext.getAuthentication() instanceof UsernamePasswordAuthenticationToken) {
                        context.delete(SecurityContext.class);
                        return repository.save(exchange, null);
                    }
                    return Mono.empty();
                });

    }

}

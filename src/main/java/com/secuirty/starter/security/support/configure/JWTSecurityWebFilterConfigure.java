package com.secuirty.starter.security.support.configure;

import com.secuirty.starter.security.config.AuthenticationJwtSpec;
import com.secuirty.starter.security.filter.SecurityContextClearFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;

public class JWTSecurityWebFilterConfigure implements SecurityWebFilterConfigure {

    private ApplicationContext applicationContext;
    private AuthenticationJwtSpec jwtSpec;

    public JWTSecurityWebFilterConfigure(ApplicationContext applicationContext, AuthenticationJwtSpec jwtSpec) {
        this.applicationContext = applicationContext;
        this.jwtSpec = jwtSpec;
    }

    @Override
    public void configure(ServerHttpSecurity security) {
        SecurityContextClearFilter clearFilter = new SecurityContextClearFilter();
        security.addFilterAt(clearFilter, SecurityWebFiltersOrder.FIRST);
        jwtSpec.configure(security);
    }
}

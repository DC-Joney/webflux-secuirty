package com.secuirty.starter.security.support.configure;

import org.springframework.security.config.web.server.ServerHttpSecurity;

public interface SecurityWebFilterConfigure {

     void configure(ServerHttpSecurity security);

}

package com.secuirty.starter.config;

import com.secuirty.starter.security.config.EnableJwtSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

@EnableJwtSecurity
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

}

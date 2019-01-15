package com.secuirty.starter.security.config;

import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;

import java.lang.annotation.*;


@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented

@ImportAutoConfiguration({ReactiveWebfluxConfiguration.class,WebfluxSecurityConfiguration.class})
public @interface EnableJwtSecurity {

}

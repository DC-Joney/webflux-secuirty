package com.secuirty.starter.security.config;

import com.secuirty.starter.security.properties.SecurityProperties;
import com.secuirty.starter.security.support.JwtMethodSecurityExpressionHandler;
import com.secuirty.starter.security.support.converter.ExceptionToJsonStringConverter;
import com.secuirty.starter.security.support.converter.ObjectToJsonStringConverter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.data.ConditionalOnRepositoryType;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.event.ApplicationContextEvent;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

import java.util.Optional;

@Log4j2
@AutoConfigureAfter(WebfluxSecurityConfiguration.class)
@ConditionalOnClass({SecurityProperties.class, AbstractOAuth2TokenAuthenticationToken.class})
class ReactiveWebfluxConfiguration implements ApplicationContextAware, ApplicationListener<ContextRefreshedEvent>, InitializingBean {

    private ConverterRegistry converterRegistry;

    private ApplicationContext applicationContext;

    @Override
    public void afterPropertiesSet(){
        this.converterRegistry = (ConverterRegistry) DefaultConversionService.getSharedInstance();
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        Optional.of(event)
                .map(ApplicationContextEvent::getApplicationContext)
                .filter(context-> context == applicationContext)
                .flatMap(context-> Optional.ofNullable(converterRegistry))
                .ifPresent(registry-> {
                    registry.addConverter(new ObjectToJsonStringConverter());
                    registry.addConverter(new ExceptionToJsonStringConverter());
                });
    }


    @Bean
    @Primary
    public MethodSecurityExpressionHandler jwtMethodSecurityExpressionHandler(){
        return new JwtMethodSecurityExpressionHandler();
    }

}


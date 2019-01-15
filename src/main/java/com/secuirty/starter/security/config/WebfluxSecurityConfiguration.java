package com.secuirty.starter.security.config;


import com.secuirty.starter.security.properties.SecurityProperties;
import com.secuirty.starter.security.support.JsonServerAuthenticationFailureHandler;
import com.secuirty.starter.security.support.JsonServerAuthenticationSuccessHandler;
import com.secuirty.starter.security.support.RSAKeyPair;
import com.secuirty.starter.security.support.configure.JWTSecurityWebFilterConfigure;
import com.secuirty.starter.security.support.configure.SecurityWebFilterConfigure;
import com.secuirty.starter.security.support.strategy.DefaultJsonStrategy;
import com.secuirty.starter.security.support.strategy.JsonStrategy;
import com.secuirty.starter.security.userdetails.DelegatingReactiveUserDetailsService;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Role;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.DelegatingServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.cors.reactive.CorsProcessor;
import reactor.core.publisher.Hooks;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Optional;


@ConditionalOnBean(DefaultMethodSecurityExpressionHandler.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass({SecurityProperties.class, AbstractOAuth2TokenAuthenticationToken.class})
@EnableConfigurationProperties(SecurityProperties.class)
class WebfluxSecurityConfiguration implements ApplicationContextAware, InitializingBean {

    private ApplicationContext applicationContext;

    @Autowired(required = false)
    private List<SecurityWebFilterConfigure> securityWebFilterConfigures;

    private DefaultMethodSecurityExpressionHandler expressionHandler;

    public WebfluxSecurityConfiguration(DefaultMethodSecurityExpressionHandler expressionHandler) {
        this.expressionHandler = expressionHandler;
        Hooks.onOperatorDebug();
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        PermissionEvaluator permissionEvaluator = getSingleBeanOrNull(PermissionEvaluator.class);
        if(permissionEvaluator != null){
            expressionHandler.setPermissionEvaluator(permissionEvaluator);
        }

        RoleHierarchy roleHierarchy = getSingleBeanOrNull(RoleHierarchy.class);
        if (roleHierarchy != null) {
            this.expressionHandler.setRoleHierarchy(roleHierarchy);
        }


    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    @Bean
    public JsonStrategy defaultJsonStrategy() {
        return new DefaultJsonStrategy();
    }

//    @Bean
//    public CorsConfigurationSource configurationSource(){
//
//        return exchange -> {
//
//        };
//
//    }

    @Bean
    @ConditionalOnMissingBean
    public DelegatingReactiveUserDetailsService delegatingReactiveUserDetailsService() {
        return new DelegatingReactiveUserDetailsService(passwordEncoder());
    }


    @Bean
    public ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler(RSAKeyPair rsaKeyPair) {
        return new JsonServerAuthenticationSuccessHandler(defaultJsonStrategy(),rsaKeyPair);
    }

    @Bean
    public ServerAuthenticationSuccessHandler defaultServerAuthenticationSuccessHandler() {
        return new DelegatingServerAuthenticationSuccessHandler(successHandlers());
    }

    @Bean
    public ServerAuthenticationFailureHandler serverAuthenticationFailureHandler() {
        return new JsonServerAuthenticationFailureHandler(defaultJsonStrategy());
    }

    private ServerAuthenticationSuccessHandler[] successHandlers() {
        return BeanFactoryUtils.beansOfTypeIncludingAncestors(
                applicationContext, ServerAuthenticationSuccessHandler.class, true, false)
                .values().toArray(new ServerAuthenticationSuccessHandler[0]);
    }




    //@Bean
    public CorsProcessor corsProcessor() {
        return (configuration, exchange) -> true;
    }


    @Lazy
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, SecurityProperties properties,AuthenticationJwtSpec jwtSpec) {

        ServerHttpSecurity.AuthorizeExchangeSpec authorizeExchangeSpec = http.authorizeExchange();

        Optional.ofNullable(properties.getPermitUrls())
                .filter(array-> array.length > 0)
                .ifPresent(arrayPath-> authorizeExchangeSpec.pathMatchers(arrayPath).permitAll());

        authorizeExchangeSpec.anyExchange().authenticated();

        ServerAccessDeniedHandler accessDeniedHandler = new JwtAccessDeniedHandler(HttpStatus.FORBIDDEN);

        http.csrf().disable()
                .requestCache()
                .and()
                .formLogin()
                .authenticationSuccessHandler(defaultServerAuthenticationSuccessHandler())
                .authenticationFailureHandler(serverAuthenticationFailureHandler())
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler)
                .and()
                .httpBasic().disable();

        Optional.ofNullable(securityWebFilterConfigures)
                .orElseGet(Collections::emptyList)
                .forEach(filterConfigure-> filterConfigure.configure(http));

        return http.build();
    }


    private <T> T getSingleBeanOrNull(Class<T> type) {
        try {
            return applicationContext.getBean(type);
        } catch (NoSuchBeanDefinitionException ignored) {}
        return null;
    }


    @Configuration
    @ConditionalOnBean(ServerHttpSecurity.class)
    @ConditionalOnClass(AuthenticationJwtSpec.class)
    public static class JwtSpecConfiguration implements ApplicationContextAware{

        private SecurityProperties properties;

        private ApplicationContext applicationContext;

        public JwtSpecConfiguration(ObjectProvider<SecurityProperties> properties) {
            this.properties = properties.getIfAvailable();
        }

        @Override
        public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
            this.applicationContext = applicationContext;
        }

        @Bean
        @ConditionalOnClass
        @ConditionalOnMissingBean
        public RSAKeyPair rsaKeyPair() {
            try {
                //实例化密钥生成器
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                //初始化密钥生成器
                keyPairGenerator.initialize(1024);
                //生成密钥对
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                //甲方公钥
                RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
                //甲方私钥
                RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
                return RSAKeyPair.builder().privateKey(privateKey).publicKey(publicKey).build();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return null;
        }


        @Bean
        @ConditionalOnMissingBean
        public AuthenticationJwtSpec authenticationJwtSpec(RSAKeyPair rsaKeyPair) {
            AuthenticationJwtSpec jwtSpec = new AuthenticationJwtSpec(applicationContext);
            jwtSpec.publicKey(rsaKeyPair.getPublicKey());
            return jwtSpec;
        }


        @Bean
        public SecurityWebFilterConfigure securityWebFilterConfigure(AuthenticationJwtSpec authenticationJwtSpec) {
            return new JWTSecurityWebFilterConfigure(applicationContext,authenticationJwtSpec);
        }


    }

}

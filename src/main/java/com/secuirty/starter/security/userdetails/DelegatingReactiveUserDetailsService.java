package com.secuirty.starter.security.userdetails;

import com.secuirty.starter.service.DemoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;


public class DelegatingReactiveUserDetailsService implements ReactiveUserDetailsService {

    @Autowired
    private DemoService demoService;

    private PasswordEncoder passwordEncoder;

    public DelegatingReactiveUserDetailsService(PasswordEncoder passwordEncoder){
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return Mono.justOrEmpty(demoService.findUser(username));
    }
}

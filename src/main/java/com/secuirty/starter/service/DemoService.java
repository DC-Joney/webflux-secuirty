package com.secuirty.starter.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Component
public class DemoService {

    @Autowired(required = false)
    private PasswordEncoder passwordEncoder;

    public Optional<UserDetails> findUser(String userName){
        return Optional.of(User.withUsername(userName).password(passwordEncoder.encode("admin")).roles("ADMIN","USER").build());
    }

    @PreAuthorize("hasRole('USER')")
    public Mono<UserDetails> findUser1(String userName){
        return Mono.justOrEmpty(User.withUsername(userName).password(passwordEncoder.encode("admin")).roles("ADMIN").build());
    }

}

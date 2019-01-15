package com.secuirty.starter.web;

import com.secuirty.starter.service.DemoService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.security.Principal;

@Log4j2
@RestController
public class DemoController {

    @Autowired
    private DemoService demoService;

    @RequestMapping("/test")
    @PreAuthorize("hasRoles('USER')")
    public Mono<Void> test(@AuthenticationPrincipal Authentication principal){
        log.info(principal);
        return Mono.empty();
    }

    @RequestMapping("/test1")
    public Mono<Void> test1(@AuthenticationPrincipal Principal principal){
        log.info(principal);
        return ReactiveSecurityContextHolder.getContext()
                .doOnNext(s-> log.info(s.getAuthentication()))
                .then(demoService.findUser1("name")).then();

    }
}

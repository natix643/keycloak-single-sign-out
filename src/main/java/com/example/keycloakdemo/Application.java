package com.example.keycloakdemo;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

import static java.util.stream.Collectors.toList;

@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@EnableWebSecurity
class KeycloakSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

    @Bean
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(keycloakAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http
                .authorizeRequests()
                .antMatchers("/protected/**").authenticated()
                .anyRequest().permitAll()
                .and().csrf().disable(); // allows GET /sso/logout, otherwise POST with CSRF token is needed
    }
}

@Controller
class AppController {

    @GetMapping
    public String index() {
        return "index";
    }

    @GetMapping("/protected/account")
    public String account(Model model, Authentication authentication) {
        List<String> roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toList());

        model.addAttribute("name", authentication.getName());
        model.addAttribute("roles", roles);
        model.addAttribute("token", currentToken(authentication));
        return "account";
    }

    private String currentToken(Authentication authentication) {
        return getKeycloakContext(authentication).getTokenString();
    }

    @GetMapping("protected/account/refresh")
    public String accountRefresh(Authentication authentication) {
        getKeycloakContext(authentication).refreshExpiredToken(false);
        return "redirect:/protected/account";
    }

    @GetMapping("/protected/account/forceRefresh")
    public String accountForceRefresh(Authentication authentication) {
        authentication.setAuthenticated(false);
        SecurityContextHolder.clearContext();
        return "redirect:/protected/account";
    }

    private RefreshableKeycloakSecurityContext getKeycloakContext(Authentication authentication) {
        Object principal = authentication.getPrincipal();

        @SuppressWarnings("unchecked")
        KeycloakPrincipal<KeycloakSecurityContext> keycloakPrincipal = (KeycloakPrincipal) principal;
        return (RefreshableKeycloakSecurityContext) keycloakPrincipal.getKeycloakSecurityContext();
    }
}

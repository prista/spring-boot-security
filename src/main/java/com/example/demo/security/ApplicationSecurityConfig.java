package com.example.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class ApplicationSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // we will authorize HTTP requests
        http.authorizeHttpRequests(configurer ->
                configurer
                        .requestMatchers(
                                new AntPathRequestMatcher("/"),
                                new AntPathRequestMatcher("/index.html")
                        ).permitAll()
                        .anyRequest()
                        .authenticated()
        );
        // use HTTP Basic Authentication
        http.httpBasic(Customizer.withDefaults());
        // disable CSRF
        http.csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }
}

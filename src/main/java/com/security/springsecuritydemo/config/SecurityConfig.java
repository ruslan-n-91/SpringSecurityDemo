package com.security.springsecuritydemo.config;

import com.security.springsecuritydemo.model.Permission;
import com.security.springsecuritydemo.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/**").hasAuthority(Permission.DEVELOPERS_READ.getPermission())
                        .requestMatchers(HttpMethod.POST, "/api/**").hasAuthority(Permission.DEVELOPERS_WRITE.getPermission())
                        .requestMatchers(HttpMethod.DELETE, "/api/**").hasAuthority(Permission.DEVELOPERS_WRITE.getPermission())
                        .anyRequest().authenticated()
                )
                .httpBasic(basic -> {
                });

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin"))
                .authorities(Role.ADMIN.getAuthorities())
                .build();

        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("user"))
                .authorities(Role.USER.getAuthorities())
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}

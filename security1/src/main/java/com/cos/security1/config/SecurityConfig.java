package com.cos.security1.config;

//import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
//import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity;
//import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록된다.
public class SecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(CsrfConfigurer::disable);
//		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.sessionManagement((sessionManagement) -> 
								sessionManagement
									.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//		http.formLogin().disable();
		http.formLogin((form)->
						form.disable());
//		http.httpBasic().disable();
		http.httpBasic((basic)->
						basic.disable());
		http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/user/**").authenticated()
				.requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
				.requestMatchers("/admin/**")
				.hasAnyRole("ADMIN").anyRequest().permitAll());

		return http.build();
	}
}
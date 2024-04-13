package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록된다.
public class SecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(CsrfConfigurer::disable);
		http.sessionManagement((sessionManagement) -> 
								sessionManagement
									.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.formLogin((form)->
						form.disable());
		http.httpBasic((basic)->
						basic.disable());
		http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/user/**").authenticated() //인증
				.requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER") //권한
				.requestMatchers("/admin/**")
				.hasAnyRole("ADMIN").anyRequest().permitAll());

		return http.build();
	}
	
	// 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
	// 비밀번호 암호화
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
}
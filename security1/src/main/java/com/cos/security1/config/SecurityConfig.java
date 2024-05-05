package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록된다.
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true) // 특정 주소 접근시 권한 및 인증을 위한 어노테이션 활성화
public class SecurityConfig {
	
	@Autowired
    private PrincipalOauth2UserService principalOauth2UserService;
    
	// 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
	// 비밀번호 암호화
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
	    http.csrf(CsrfConfigurer::disable);
	    http.authorizeHttpRequests(authorize -> authorize
	            // "/user/~" 이 주소로 들어오면 인증이 필요함 -> 인증만 되면 들어갈 수 있는 주소!
	            .requestMatchers("/user/**").authenticated()
	            // "/manager/~" 이 주소로 들어가기 위해서는 Admin과 Manager 권한이 있는 사람만 들어올 수 있음
	            .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
	            // "/admin/**" 이 주소로 들어가기 위해서는 Admin 권한이 있는 사람만 들어올 수 있음
	            .requestMatchers("/admin/**").hasAnyRole("ADMIN")
	            // 설정한 주소가 아니면 누구나 들어갈 수 있음
	            .anyRequest().permitAll())
	    		.formLogin((formLogin) ->
	    		formLogin
	    		.loginPage("/loginForm")
	    		.loginProcessingUrl("/login") // login주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행
	    		.defaultSuccessUrl("/")
	    		)
	    		.oauth2Login((oauth2Login) ->
	    		oauth2Login
	    		.loginPage("/loginForm")
                .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                        .userService(principalOauth2UserService)
                        )
	    		);
		return http.build();
	}
}
	

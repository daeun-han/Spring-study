package com.cos.security1.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;



@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
	
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    

    @Autowired
    private UserRepository userRepository;
	
    // 구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration : "+userRequest.getClientRegistration()); // registrationId로 어떤 OAuth로 로그인 했는지 확인 가능
        System.out.println("getAccessToken : "+userRequest.getAccessToken().getTokenValue());
        
        OAuth2User oauth2User = super.loadUser(userRequest);
        
        
        System.out.println("getAttributes : "+ oauth2User.getAttributes());
        
        String provider = userRequest.getClientRegistration().getClientId(); // google
        String providerId = oauth2User.getAttribute("sub");
        String username = provider+"_"+providerId; // google_105431086732917734236
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oauth2User.getAttribute("email");
        String role = "ROLE_USER";
        
        // 이미 회원가입이 되어있다면 ?
        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }

        // 회원가입을 강제로 진행
        return new PrincipalDetails(userEntity, oauth2User.getAttributes());
    }
}
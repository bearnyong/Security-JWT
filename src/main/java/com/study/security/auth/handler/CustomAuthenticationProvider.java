package com.study.security.auth.handler;

import com.study.security.auth.model.DetailsUser;
import com.study.security.auth.service.DetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired //가지고 있는 bean의 목록 중 가장 유사한 친구 넣어줌
    private DetailsService detailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken laginToken = (UsernamePasswordAuthenticationToken) authentication; //토큰 꺼내옴(id, pass 전달)
        String id = laginToken.getName();
        String pass = (String) laginToken.getCredentials();

        DetailsUser detailsUser = (DetailsUser) detailsService.loadUserByUsername(id);

        if (!passwordEncoder.matches(pass, detailsUser.getPassword())) {
            throw new BadCredentialsException(pass + "는 비밀번호가 아닙니다.");
        }
        return new UsernamePasswordAuthenticationToken(detailsUser, pass, detailsUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}

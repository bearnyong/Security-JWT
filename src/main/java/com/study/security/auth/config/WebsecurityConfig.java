package com.study.security.auth.config;

import com.study.security.auth.filter.CustomAuthenticaiotnFilter;
import com.study.security.auth.filter.JwtAuthorizationFilter;
import com.study.security.auth.handler.CustomAuthFailUserHandler;
import com.study.security.auth.handler.CustomAuthLoginSuccessHandler;
import com.study.security.auth.handler.CustomAuthenticationProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //권한 정보들을 메소드 단에서 ... 어쩌고
public class WebsecurityConfig {
    /*
     * 1. 정적 자원에 대한 인증된 사용자의 접근을 설정하는 메서드
     * @return WebSeruciryCusomizer */

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()); //필터에서 제외시킬 애들
    }

    /**
     * 2. security filter chain 설정
     * @return SecurityFilterChain */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /**/
        http.csrf/*사용자의 정보 가로챔*/().disable() //불필요한 리소스가 낭비되기 때문에 비활성화 시킨다.
                .headers(header -> header.frameOptions().sameOrigin()) //sameOrigin: 동일한 사이트에서 제공되는 프레임만 보여주겠다.
                .authorizeRequests()
                .anyRequest().permitAll() //모든 권한을 다 허용해줄게~ 여기까지 권한 설정 끝
                .and()
                .addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션을 사용하지 않겠다. 왜느냐면 토큰 기반으로 쓰기 떄문에
                .and()
                .formLogin().disable() //기본 로그인화면으로 이동 사용하지 않겠다.
                .addFilterBefore(customAuthenticaiotnFilter(), UsernamePasswordAuthenticationFilter.class)
                .httpBasic().disable();
        return http.build();
    }

    /**
     * 3. Authentization의 인증 메서드를 제공하는 매니저로 Provider의 인터페이스를 의미한다.
     * @return AuthenticationManager */
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(customAuthenticationProvider());
    }

    /**
     * 4. 사용자의 아이디와 패스워드를 DB와 검증하는 handler이다
     * @return CustomAuthenticationProvider */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    /**
     * 5. 비밀번호를 암호화하는 인코더
     * @return BCryptPasswordEncoder */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 6. 사용자의 인증 요청을 가로채서 로그인 로직을 수행하는 필터
     * @return CustomAuthenticationFilter */
    @Bean
    public CustomAuthenticaiotnFilter customAuthenticaiotnFilter() {
        CustomAuthenticaiotnFilter customAuthenticaiotnFilter = new CustomAuthenticaiotnFilter(authenticationManager());
        customAuthenticaiotnFilter.setFilterProcessesUrl("/login");
        customAuthenticaiotnFilter.setAuthenticationSuccessHandler(customAuthLoginSuccessHandler()); //로그인 성공시
        customAuthenticaiotnFilter.setAuthenticationFailureHandler(customAuthFailUserHandler()); //로그인 실패시
        customAuthenticaiotnFilter.afterPropertiesSet();

        return customAuthenticaiotnFilter;
    }

    /**
     * 7. spring security 기반의 사용자의 정보가 맞을 경우 결과를 수행하는 handler
     * @return customAuthLoginSuccessHandler */
    @Bean
    public CustomAuthLoginSuccessHandler customAuthLoginSuccessHandler() {
        return new CustomAuthLoginSuccessHandler();
    }

    /**
     * 8. Spring security의 사용자 정보가 맞지 않은 경우 행되는 메서드
     * @return CustomAuthFailUserHandler */
    @Bean
    public CustomAuthFailUserHandler customAuthFailUserHandler() {
        return new CustomAuthFailUserHandler();
    }

    /**
     * 9. 사용자 요청시 수행되는 메소드
     *
     * @return JwtAuthorizationFilter
     */
    public JwtAuthorizationFilter jwtAuthorizationFilter() {
        return new JwtAuthorizationFilter(authenticationManager());
    }
}

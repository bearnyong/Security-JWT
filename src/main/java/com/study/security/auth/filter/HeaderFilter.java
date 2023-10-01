package com.study.security.auth.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
* cors(크로스 브라우징 공격) 설정을 위한 filter 설정
* -위조 사이트 공격을 막기 위한*/
public class HeaderFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse) response;
        res.setHeader("Access-Control-Allow-Origin", "*"/*모든 것을 다 허용*/); //location3000 -> 다른 외부 요청의 응답을 허용할 것인가?
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"); //외부 요청에 허용할 메서드
        res.setHeader("Access-Control-Max-Age", "3600"); //캐시에 대한 유효시간 (1시간)
        res.setHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization, X-XSRF-token"); //요청 패킷에 대한 응답 헤더
        res.setHeader("Access-Control-Allow-Credentials", "false"); //무조건 자격 증명을 확인할 것인가?
        chain.doFilter(request, response);
    }
}

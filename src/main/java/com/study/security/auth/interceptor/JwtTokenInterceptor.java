package com.study.security.auth.interceptor;

import com.study.security.common.AuthConstants;
import com.study.security.common.utils.TokenUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.rmi.RemoteException;

public class JwtTokenInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String header = request.getHeader(AuthConstants.AUTH_HEADER);
        String token = TokenUtils.splitHeader(header);

        if (token != null) {
            //토큰이 유효한지 -> 우리가 만든 토큰인지 확인
            if (TokenUtils.isValidToken(token)) {
                return true;
            } else {
                //토큰 시간이 만료되었거나 ... 
                throw new RemoteException("token이 만료도었습니다.");
            }
        } else {
            throw new RemoteException("token 정보가 없습니다.");
        }
    }
}

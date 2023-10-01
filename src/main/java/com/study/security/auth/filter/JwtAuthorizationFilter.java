package com.study.security.auth.filter;

import com.study.security.auth.model.DetailsUser;
import com.study.security.common.AuthConstants;
import com.study.security.common.OhgiraffersRole;
import com.study.security.common.utils.TokenUtils;
import com.study.security.user.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import org.json.simple.JSONObject;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        /*
        * 권한이 필요없는 리소스*/
        List<String> roleLessList = Arrays.asList(
                "/singup"
        );

        try {
            if (roleLessList.contains(request.getRequestURI())) {
                chain.doFilter(request, response);
                return;
            }

            String header = request.getHeader(AuthConstants.AUTH_HEADER);

            if (header != null && !header.equalsIgnoreCase("")) {
                String token = TokenUtils.splitHeader(header);
                System.out.println(token);

                if (TokenUtils.isValidToken(token)) { //토큰이 활성화가 되어있는 상태라면
                    System.out.println("to : ");
                    Claims claims = TokenUtils.getClaimsFormToken(token);
                    DetailsUser authentication = new DetailsUser();

                    //매 요청 시 DB IO를 발생하게 됨 (사용자가 늘어날수록 어플리케이션의 성능이 저하됨)
                    User user = new User();
                    user.setUserName(claims.get("userName").toString());
//                    user.setUserEmail(claims.get("userEmail").toString());
                    user.setRole(OhgiraffersRole.valueOf(claims.get("Role").toString()));

                    authentication.setUser(user);

                    AbstractAuthenticationToken authenticationToken = UsernamePasswordAuthenticationToken.authenticated(authentication, token, authentication.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    chain.doFilter(request, response);
                } else {
                    throw new RuntimeException("토큰이 유효하지 않습니다.");
                }
            } else {
                throw new RuntimeException("토큰이 존재하지 않습니다.");
            }
        } catch (Exception e) {
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json");
            PrintWriter printWriter = response.getWriter();
            JSONObject jsonObject = jsonresponseWrapper(e);
            printWriter.print(jsonObject);
            printWriter.flush();
            printWriter.close();
        }
    }

    /**
     * 토큰 관련되 ㄴException 발생 시 예외 응답
     */
    private JSONObject jsonresponseWrapper(Exception e) {
        String resultMsg = "";
        if (e instanceof ExpiredJwtException) {
            resultMsg = "Token Expired";
        } else if (e instanceof SignatureException) {
            resultMsg = "TOKEN SignatureException Login";
        }
        // JWT 토큰내에서 오류 발생 시
        else if (e instanceof JwtException) {
            resultMsg = "TOKEN Parsing JwtException";
        }
        // 이외 JTW 토큰내에서 오류 발생
        else {
            resultMsg = "OTHER TOKEN ERROR";
        }

        HashMap<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("status", 401);
        jsonMap.put("message", resultMsg);
        jsonMap.put("reason", e.getMessage());
        JSONObject jsonObject = new JSONObject(jsonMap);
        return jsonObject;
    }
}

package com.study.security.auth.handler;

import com.study.security.auth.model.DetailsUser;
import com.study.security.common.AuthConstants;
import com.study.security.common.utils.ConvertUtil;
import com.study.security.common.utils.TokenUtils;
import com.study.security.user.entity.User;
import org.json.simple.JSONObject;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Objects;

@Configuration
public class CustomAuthLoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        //로그인 성공시 핸들러
        User user = ((DetailsUser) authentication.getPrincipal()).getUser();
        JSONObject jsonValue = (JSONObject) ConvertUtil.convertObjectToJsonObject(user);
        HashMap<String, Object> responseMap = new HashMap<>();

        JSONObject jsonObject;
        if (user.getState().equals("N")) {
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "휴먼상태인 계정입니다.");
        } else {
            String token = TokenUtils.getnerateJwtToken(user);
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "로그인 성공");

            response.addHeader(/*꾸준하게 사용할 수 있는 상수 필드*/AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + token);
        }

        jsonObject = new JSONObject(responseMap);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");

        PrintWriter printWriter = response.getWriter();
        printWriter.print(jsonObject);
        printWriter.flush();
        printWriter.close();
    }
}

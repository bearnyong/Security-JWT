package com.study.security.common.utils;

import com.study.security.user.entity.User;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/*
 * 토큰을 관리하기 위한 utils 모음 클래스
 *
 * yml -> jwt-key(시크릿키), jwt-time(타임) 설정이 필요하다
 * jwt lib 버전은 "io.jsonwebtoken:jjwt:0.9.1" 사용*/
@Component
public class TokenUtils {
    //토큰을 복호화하는 유틸리티
    private static String jwtSecretkey;
    private static Long tokenValidateTime; //바로 못 가져와서 setter

    @Value("${jwt.key}") //yml에서 확인해봐 신기함
    public void setJwtSecretkey(String jwtSecretkey) { //여기서 static을 적으면 또 바로 못가져옴 그래서 빼
        TokenUtils.jwtSecretkey = jwtSecretkey;
    }

    @Value("${jwt.time}")
    public void setTokenValidateTime(Long tokenValidateTime) {
        TokenUtils.tokenValidateTime = tokenValidateTime;
    }

    /*
     * header의 token을 분리하는 메서드
     * @param header : Authrization의 header 값을 가져온다.
     * @return token : Authrization의 token 부분을 반환한다. */

    public static String splitHeader(String header) {
        if (!header.equals("")) {
            return header.split(" ")[1]; //관례같은것임...
        } else {
            return null;
        }
    }

    /*
     * 유효한 토큰인지 확인하는 메서드
     * @param token : 토큰
     * @return boolean : 유효 여부
     * @throws ExpiredJwtException, {@Link JwtException} {@Link NullPointerException}*/
    public static boolean isValidToken(String token) {
        try {
            Claims claims = getClaimsFormToken(token);
            //복호화가 되면 이 토큰은 살아있는 토큰이다.
            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
            return false;
        } catch (JwtException e) {
            e.printStackTrace();
            return false;
        } catch (NullPointerException e) {
            e.printStackTrace();
            return false;
        }
    }

    /*
     * 토큰을 보호화 하는 메서드
     * @pzram token
     * @return CLaims(데이터의 작은 단위, 페이로드에 담겨져 있는 부분) */
    public static Claims getClaimsFormToken(String token) {
        return Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecretkey))
                .parseClaimsJws(token).getBody(); //바디를 반환시켜줘! -> 클레임이라는 데이터 단위로 넘어가게됨
    }

    /**
     * token을 생성하는 메서드
     *
     * @param user - userEntity
     * @returnString - token
     */
    public static String getnerateJwtToken(User user) {
        Date expireTime = new Date(System.currentTimeMillis() + tokenValidateTime); //현재 시간부터 토큰이 존재하는 시간
        JwtBuilder builder = Jwts.builder()
                .setHeader(createHeader()) //토큰을 만들떄만 사용하는 헤더
                .setClaims(createClaims(user)) //사용자에게 보내줄 데이터..
                .setSubject("ohgiraffers token : " + user.getUserNo())
                .signWith(SignatureAlgorithm.HS256, createSignature())
                .setExpiration(expireTime);

        return builder.compact();
    }

    /**
     * token의 header를 설정하는 부분이다.
     * @return Map<String, Object> - header의 설정 정보*/
    private static Map<String, Object> createHeader() {
        Map<String, Object> header = new HashMap<>();

        header.put("type", "jwt");
        header.put("alg", "HS256");
        header.put("date", System.currentTimeMillis());

        return header;
    }

    /**
     * 사용자 정보를 기반으로 클레임을 생성해주는 메서드다.
     *
     * @param user - 사용자 정보
     * @return Map<String, Object> - cliams 정보
     */
    private static Map<String, Object> createClaims(User user) {
        Map<String, Object> claims = new HashMap<>(); //사용자의 정보를 담아주는 부분
        claims.put("userName", user.getUserName());
        claims.put("Role", user.getRole());
        claims.put("userEmail", user.getUserEmail());

        return claims;
    }

    /**
     * JWT 서명을 발급해주는 메서드이다.
     *
     * @return key
     */
    private static Key createSignature() {
        byte[] secretByters = DatatypeConverter.parseBase64Binary(jwtSecretkey);
        return new SecretKeySpec(secretByters, SignatureAlgorithm.HS256.getJcaName());
    }
}

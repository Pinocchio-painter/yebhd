package com.xxxx.server.config.ecurity;
/*
 * JwtToken 工具类*/

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenUtil {
    // 用户名的key
    private static final String CLAIM_KEY_USERNAME = "sub";
    // jwt创建时间
    private static final String CLAIM_KEY_CREATED = "created";
    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private Long expiration;

    /*根据用户信息进行生成token*/
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
        claims.put(CLAIM_KEY_CREATED, new Date());
        return generateToken(claims);
    }

    /*
     * 从token中获取用户名
     * */
    public String getUsernameFromToken(String token) {
        String username;
        try {
            Claims claims = getClaimsFormToken(token);
            username = claims.getSubject();
        } catch (Exception e) {
            username = null;
        }
            return username;
    }

    /** 
    * @Description: 验证token是否有效
            * @Param: token
            * @Author: 苏振琦
            */
    
    public boolean validateToken(String token, UserDetails userDetails) {
        String username = getUsernameFromToken(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }
/** 
* @Description: 判断token是否可以被刷新
        * @Param: 
        * @Author: 苏振琦
        */

    public boolean canRefresh(String token){
        return !isTokenExpired(token);
    }

/** 
* @Description: 刷新token
        * @Param: token
        * @Author: 苏振琦
        */

    public String refreshToken(String token){
        Claims claims = getClaimsFormToken(token);
        claims.put(CLAIM_KEY_CREATED, new Date());
        return generateToken(claims);

    }


    /** 
    * @Description: 判断token是否失效
            * @Param: token
            * @Author: 苏振琦
            */
    
    private boolean isTokenExpired(String token) {
            Date expireDate = getExpiredDateFromToken(token);
            return expireDate.before(new Date());
        }

    /** 
    * @Description: 获取token中失效的时间
            * @Param: 
            * @Author: 苏振琦
            */
    
    private Date getExpiredDateFromToken(String token) {
        Claims claims = getClaimsFormToken(token);
        return claims.getExpiration();
    }


    /** 
    * @Description: 从token中获取荷载
            * @Author: 苏振琦
            */
    
    private Claims getClaimsFormToken(String token) {
        Claims claims = null;
        try {
            claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return claims;
    }


    /*
     * 根据荷载生成JWT TOKEN*/
    private String generateToken(Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(generateExpirationDate())
                .signWith(SignatureAlgorithm.ES512, secret)
                .compact();
    }

    /*
     * 生成token失效时间*/
    private Date generateExpirationDate() {
        return new Date(System.currentTimeMillis() + expiration * 1000);
    }

}

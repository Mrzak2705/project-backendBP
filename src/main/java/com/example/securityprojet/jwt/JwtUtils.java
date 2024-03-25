package com.example.securityprojet.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.securityprojet.bean.User;
import com.example.securityprojet.common.SecurityParams;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private String jwtSecret;

    public String generateJwtToken(Authentication authentication) {

        User userPrincipal = (User) authentication.getPrincipal();
        Collection<String> roles = new ArrayList<>();
        if (userPrincipal.getAuthorities() != null) {
            userPrincipal.getAuthorities().forEach(a->roles.add(a.getAuthority()));
        }

        String jwt= JWT.create()
                .withSubject(userPrincipal.getUsername())
                .withSubject(userPrincipal.getPrenom())
                .withSubject(userPrincipal.getNom())
                .withArrayClaim("roles",roles.toArray(new String[roles.size()]))
                .withExpiresAt(new Date(System.currentTimeMillis()+ SecurityParams.EXPIRATION))
                .sign(Algorithm.HMAC256(SecurityParams.SECRET));
        return jwt;
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}

package com.cts.authentication;

import java.util.Date;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey; // Using javax.crypto.SecretKey

import com.cts.authentication.service.JwtBlacklistService;

@Component
public class JwtUtil {
    // For production, this secret should be loaded from a secure configuration (e.g., environment variable, Vault)
    // and not generated dynamically like this. This is for quick setup.
    private final SecretKey jwtSecret = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    private final long jwtExpirationMs = 86400000; // Token valid for 24 hours (86,400,000 milliseconds)

    @Autowired
    private JwtBlacklistService jwtBlacklistService;

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .claim("role", userDetails.getAuthorities().stream().findFirst().map(a -> a.getAuthority()).orElse("ROLE_USER")) // Safely get role
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(jwtSecret, SignatureAlgorithm.HS512) // Explicitly use HS512
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        if (jwtBlacklistService.isTokenBlacklisted(token)) {
            return false; // Reject blacklisted tokens
        }

        try {
            Claims claims = extractClaims(token);
            final String username = claims.getSubject();
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(claims));
        } catch (Exception e) {
            // Log specific JWT exceptions (e.g., ExpiredJwtException, SignatureException, MalformedJwtException)
            // logger.error("JWT validation error: {}", e.getMessage());
            return false;
        }
    }

    private Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(jwtSecret)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }
}
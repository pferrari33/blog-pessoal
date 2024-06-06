package com.generation.blogpessoal.security;

import java.security.Key; 
import java.util.Date; 
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtService {

    // É uma constante que gera uma chave para encodar as informações do token
    public static final String SECRET = "0618f46fa1e100a683ce7fc06fffaf431d1384763d2b33281cec25dfc289abfe";

    // Token palima@gmail.com 2024-06-04 9:40 assinatura

    // Assinatura token
    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /*
     * Claims - declarações usuário / declaração data que expira / declaração da assinatura
     * nesse caso assinatura
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey()).build()
                .parseClaimsJws(token).getBody();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /*
     * Recuperar os dados da parte sub do claim onde encontramos o email (usuário)
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /*
     * Data que o token expira
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /*
     * Valida se a data que o token expira está dentro da validade ou seja a data atual ainda não atingiu essa data
     */
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /*
     * Validar se o usuário que foi extraído do token condiz com o usuário que a userDetails tem e se está dentro da
     * data de validade ainda o token
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /*
     * Objetivo de calcular o tempo de validade do token, formar o claim com as informações do token
     */
    private String createToken(Map<String, Object> claims, String userName) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    /*
     * Gerar o token puxando os claims formados no método anterior
     */
    public String generateToken(String userName) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userName);
    }
}

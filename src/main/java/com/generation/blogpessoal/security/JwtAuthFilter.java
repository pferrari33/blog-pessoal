package com.generation.blogpessoal.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/*
 * objetivos da classe
 * trazer as validações do token feitas da JWTService
 * confirmar se o token está chegando pelo Header quando o usuário já estiver logado
 * tratar o token
 */

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtService jwtService;  
    
    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;  
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
    	//informando que o insomnia o token vem via header e com a nomenclatura Authorization
        String authHeader = request.getHeader("Authorization");
        
        //inicio null
        String token = null;
        
        //inicia user
        String username = null;
        
        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {  
            	
            	//metodo string retirando 7 caracteres
                token = authHeader.substring(7);
                username = jwtService.extractUsername(token);
            }
            //validação de existe um username que foi extraido do token e não temos regras configuradas de autorização
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);  
                
                if (jwtService.validateToken(token, userDetails)) {  
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            
            filterChain.doFilter(request, response); 
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException e) { 
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }
    }
}

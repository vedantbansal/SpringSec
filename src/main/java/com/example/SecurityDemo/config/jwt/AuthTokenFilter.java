package com.example.SecurityDemo.config.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Custom Filter for authenticating JWT tokern
@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JWTUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            // 1. Extract JWT token from the Authorization header
            String jwt = jwtUtils.getJWTFromHeader(request);
            // 2. If the token exists and is valid
            if (jwt != null && jwtUtils.validateJWTToken(jwt)) {
                // 3. Extract the username from the token
                String username = jwtUtils.getUsernameFromJWTToken(jwt);
                // 4. Load user details (authorities, credentials, etc.) from the database
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                // 5. Create an authenticated token for Spring Security context
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                // 6. Attach additional details (e.g., IP address) to the token
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // 7. Set the authentication in the security context
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        } catch (Exception e) {
        }
        // 8. Continue the request through the filter chain
        filterChain.doFilter(request, response);
    }

}

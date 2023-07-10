package org.sid.secspring.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AuthController {
    private JwtDecoder jwtDecoder;
    private JwtEncoder jwtEncoder;
    private AuthenticationManager authenticationManager;
    private UserDetailsService userDetailsService;

    public AuthController(JwtDecoder jwtDecoder, JwtEncoder jwtEncoder, AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
        this.jwtDecoder = jwtDecoder;
        this.jwtEncoder = jwtEncoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }
    @PostMapping("/token")
    public ResponseEntity<Map<String,String>> jwtToken(
            String grantType,
            String username,
            String password,
            boolean withRefreshToken,
            String refreshToken){
        String subject=null;
        String scope=null;
        if (grantType.equals("password")){
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            subject=authentication.getName();
            scope=authentication.getAuthorities()
                    .stream().map(auth->auth.getAuthority())
                    .collect(Collectors.joining(" "));
        }else if (grantType.equals("refreshTokens")){
            if(refreshToken==null){
                return new ResponseEntity<>(Map.of("errorMessage","Refresh token is required"), HttpStatus.UNAUTHORIZED);
            }
            Jwt decodeJwt = null;
            try {
                decodeJwt = jwtDecoder.decode(refreshToken);
            } catch (JwtException e) {
                return new ResponseEntity<>(Map.of("errorMessage",e.getMessage()), HttpStatus.UNAUTHORIZED);
            }
            subject=decodeJwt.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            scope=authorities.stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));


        }

        Map<String,String> idToken=new HashMap<>();
        Instant instant=Instant.now();
        JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken?5:30, ChronoUnit.MINUTES))
                .issuer("Security-Service")
                .claim("scope",scope)
                .build();
        String jwtAccessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken",jwtAccessToken);
        if (withRefreshToken) {
            JwtClaimsSet jwtClaimsSetRefresh=JwtClaimsSet.builder()
                    .subject(subject)
                    .issuedAt(instant)
                    .expiresAt(instant.plus(30, ChronoUnit.MINUTES))
                    .issuer("Security-Service")
                    .build();
            String jwtRefreshToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
            idToken.put("refreshToken",jwtRefreshToken);


        }
        return new ResponseEntity<>(idToken,HttpStatus.OK);

    };
}

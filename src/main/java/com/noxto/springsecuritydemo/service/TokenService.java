package com.noxto.springsecuritydemo.service;

import com.noxto.springsecuritydemo.dto.TokenPairDto;
import com.noxto.springsecuritydemo.exception.ExpiredTokenException;
import jakarta.annotation.Nonnull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.time.Instant;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    @Value("${jwt.access-token.expiry}")
    long accessTokenExpiry;
    @Value("${jwt.refresh-token.expiry}")
    long refreshTokenExpiry;
    @Autowired
    private CustomUserService customUserService;

    public TokenPairDto generateJWT(Authentication auth) {
        Instant now = Instant.now();

        String scope = auth
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        var claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .subject(auth.getName())
                .claim("roles", scope)
                .expiresAt(now.plusSeconds(accessTokenExpiry))  // 5 seconds expiration for access token
                .build();

        var tokenEncoderParams = JwtEncoderParameters.from(claims);
        var token = jwtEncoder.encode(tokenEncoderParams).getTokenValue();

        var refreshClaims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .subject(auth.getName())
                .claim("roles", scope)
                .expiresAt(now.plusSeconds(refreshTokenExpiry))  // 24 hours expiration for refresh token
                .build();

        var refreshEncoderParams = JwtEncoderParameters.from(refreshClaims);
        var refreshToken = jwtEncoder.encode(refreshEncoderParams).getTokenValue();

        return new TokenPairDto(token, refreshToken);
    }

    public boolean isTokenValid(@Nonnull String refreshToken) throws ExpiredTokenException {
        Jwt decodedToken = jwtDecoder.decode(refreshToken);

        var username = decodedToken.getSubject();
        var userDetails = customUserService.loadUserByUsername(username);
        var decodedRole = (String) decodedToken.getClaim("roles");

        if(Objects.requireNonNull(decodedToken.getExpiresAt()).isBefore(Instant.now())){
            log.error("token is expired!!!!");
            throw new ExpiredTokenException("Refresh token is expired");
        }

        if (ObjectUtils.isEmpty(userDetails) && !userDetails.getAuthorities().contains(decodedRole)){
            throw new InvalidBearerTokenException("Invalid refresh token ");
        }

        log.info("AccessToken Subject: " + decodedToken.getSubject() + " role " + decodedRole);
        return true;
    }

}

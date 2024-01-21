package com.noxto.springsecuritydemo.service;

import com.noxto.springsecuritydemo.dto.LoginDto;
import com.noxto.springsecuritydemo.dto.TokenPairDto;
import com.noxto.springsecuritydemo.dto.UserDto;
import com.noxto.springsecuritydemo.entity.Role;
import com.noxto.springsecuritydemo.entity.User;
import com.noxto.springsecuritydemo.repository.RoleRepository;
import com.noxto.springsecuritydemo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class AuthService {
    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtDecoder jwtDecoder;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    TokenService tokenService;
    @Autowired
    CustomUserService customUserService;

    public User register(UserDto user) {
        Optional<Role> userRole = roleRepository.findByRole(user.getRole()).or(() -> roleRepository.findByRole("USER"));
        Set<Role> userRoleSet = new HashSet<>();
        userRoleSet.add(userRole.get());

        var newUser = new User(user.getUsername(), passwordEncoder.encode(user.getPassword()), user.getFirstName(),
                user.getLastName(), userRoleSet);

        return userRepository.save(newUser);
    }

    public LoginDto login(LoginDto loginDto) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword()));

        if (authentication.isAuthenticated()) {
            TokenPairDto tokenPair = tokenService.generateJWT(authentication);
            loginDto.setJwtToken(tokenPair.getAccessToken());
            loginDto.setRefreshToken(tokenPair.getRefreshToken());
            loginDto.setPassword("");
        }
        return loginDto;
    }


    public TokenPairDto refreshToken(String refreshToken) {
        Jwt decodedToken = jwtDecoder.decode(refreshToken);
        var username = decodedToken.getSubject();
        var userDetails = customUserService.loadUserByUsername(username);

        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails.getUsername(), null, userDetails.getAuthorities());

        // Set the Authentication object in the SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return tokenService.generateJWT(authentication);
    }

}

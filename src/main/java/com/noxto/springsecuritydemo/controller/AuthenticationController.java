package com.noxto.springsecuritydemo.controller;

import com.noxto.springsecuritydemo.dto.LoginDto;
import com.noxto.springsecuritydemo.dto.TokenPairDto;
import com.noxto.springsecuritydemo.dto.UserDto;
import com.noxto.springsecuritydemo.entity.User;
import com.noxto.springsecuritydemo.exception.ExpiredTokenException;
import com.noxto.springsecuritydemo.service.AuthService;
import com.noxto.springsecuritydemo.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*")
@Slf4j
public class AuthenticationController {
    @Autowired
    AuthService authService;
    @Autowired
    TokenService tokenService;
    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@RequestBody UserDto user) {
        log.info("Registering user: " + user.toString());
        User createdUser = authService.register(user);
        String role = createdUser.getRoles().stream().findFirst().get().getRole();

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(new UserDto(createdUser.getUsername(), "", createdUser.getFirstName(),
                        createdUser.getLastName(), role));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginDto> login(@RequestBody LoginDto loginDto) {

        return ResponseEntity.status(HttpStatus.OK).body(authService.login(loginDto));
    }

    @GetMapping({"", "/"})
    public ResponseEntity<String> def() {
        return ResponseEntity.ok("Default Auth Controller");
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<TokenPairDto> refreshToken(@RequestBody TokenPairDto tokenPairDto) throws ExpiredTokenException {
        var refreshToken = tokenPairDto.getRefreshToken();
        TokenPairDto token;

            if (tokenService.isTokenValid(refreshToken)) {
                log.info("Refresh Token: " + refreshToken);
                token = authService.refreshToken(refreshToken);
            }else{
                throw new ExpiredTokenException("The access token has expired.");
            }

        log.info("Refresh completed !!");
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }
}

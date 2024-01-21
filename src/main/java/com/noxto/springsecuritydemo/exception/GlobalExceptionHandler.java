package com.noxto.springsecuritydemo.exception;

import com.nimbusds.jose.proc.BadJWSException;
import com.noxto.springsecuritydemo.dto.OAuth2Error;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler({BadJWSException.class, JwtValidationException.class, ExpiredTokenException.class, InvalidBearerTokenException.class})
    public ResponseEntity<OAuth2Error> handleTokenExceptions(Exception e){
        String errorCode = OAuth2ErrorCodes.INVALID_TOKEN;
        var errorDescription = "Token Validation Failed !!";
        var errorHint = "Check the validity of your token";

        if (e instanceof BadJWSException){
            errorHint = "Log in again to obtain a new valid token";
        }else if (e instanceof InvalidBearerTokenException){
            errorHint = "Log in to obtain a valid access token";
        }


        var oAuth2Error = new OAuth2Error(errorCode, errorDescription, errorHint);

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(oAuth2Error);

    }
}

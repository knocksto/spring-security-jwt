package com.noxto.springsecuritydemo.exception;

public class ExpiredTokenException extends Exception {
    public ExpiredTokenException(String refreshTokenIsExpired) {
        super(refreshTokenIsExpired);
    }
}

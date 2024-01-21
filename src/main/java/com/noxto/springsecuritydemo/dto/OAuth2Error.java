package com.noxto.springsecuritydemo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2Error {
    private String error;
    private String errorDescription;
    private String errorHint;
}

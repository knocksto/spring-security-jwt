package com.noxto.springsecuritydemo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenPairDto {
    private String accessToken;
    private String refreshToken;
    private String errorMessage = "";

    public TokenPairDto(String accessToken, String refreshToken){
        this(accessToken, refreshToken, "");
    }

}

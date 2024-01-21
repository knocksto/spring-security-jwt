package com.noxto.springsecuritydemo.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginDto {
    private String username;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String password;
    private String jwtToken;
    private String refreshToken;

}

package com.noxto.springsecuritydemo.controller;

import com.noxto.springsecuritydemo.dto.UserDto;
import com.noxto.springsecuritydemo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/user")
@CrossOrigin("*")
public class UserController {

    @Autowired
    UserRepository userRepository;
    @GetMapping({"","/"})
    public ResponseEntity<String> getHome(){
        return ResponseEntity.ok("Welcome Home User!!!");
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> getUsers(){
        return ResponseEntity.ok(userRepository
                .findAll()
                .stream()
                .map(u -> new UserDto(
                        u.getUsername(),
                        "",
                        u.getFirstName(),
                        u.getLastName(),
                        u.getRoles().toString()))
                .toList());
    }
}

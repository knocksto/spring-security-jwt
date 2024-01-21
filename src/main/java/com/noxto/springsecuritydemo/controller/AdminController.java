package com.noxto.springsecuritydemo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/admin")
@CrossOrigin("*")
@RestController
public class AdminController {
    @GetMapping({"","/"})
    public ResponseEntity<String> getAdminPage(){
        return ResponseEntity.ok("Hello Admin, Welcome!!!");
    }
}

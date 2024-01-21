package com.noxto.springsecuritydemo;

import com.noxto.springsecuritydemo.entity.Role;
import com.noxto.springsecuritydemo.entity.User;
import com.noxto.springsecuritydemo.repository.RoleRepository;
import com.noxto.springsecuritydemo.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

@SpringBootApplication
@Slf4j
public class SpringSecurityDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityDemoApplication.class, args);
    }

    @Bean
    CommandLineRunner commandLineRunner(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder encoder) {
        return args -> {
            if (userRepository.findUserByUsername("ADMIN").isPresent()) return;

            Role adminRole = new Role("ADMIN");
            Role userRole = new Role("USER");

            roleRepository.save(adminRole);
            roleRepository.save(userRole);

            var regularUser = new User(
                    "max",
                    encoder.encode("password"),
                    "Maxwell",
                    "Sarpong",
                    Collections.singleton(userRole));

            log.info("new user saved successfully!!!" + userRepository.save(regularUser));

            var adminUser = new User(
                    "enock",
                    encoder.encode("password"),
                    "Enock",
                    "Boadi-Ansah",
                    Collections.singleton(adminRole));

            log.info("new admin user saved successfully!!!" + userRepository.save(adminUser));
        };
    }
}

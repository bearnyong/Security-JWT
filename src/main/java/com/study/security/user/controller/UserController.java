package com.study.security.user.controller;

import com.study.security.user.entity.User;
import com.study.security.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@Controller
@RequestMapping
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/singup")
    public String singup(@RequestBody User user) {
        user.setUserPass(passwordEncoder.encode(user.getUserPass()));
        user.setState("Y");

        User value = userRepository.save(user);
        if (Objects.isNull(value)) {
            return "회원 가입 실패";
        } else {
            return "회원 가입 완료";
        }
    }
}

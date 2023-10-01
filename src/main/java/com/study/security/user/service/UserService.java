package com.study.security.user.service;

import com.study.security.user.entity.User;
import com.study.security.user.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> findUser(String id) {
        Optional<User> user = userRepository.findByUserId(id);
        System.out.println("user : " + user);
        return user;
    }
}

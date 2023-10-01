package com.study.security.common;

public enum OhgiraffersRole {
    //enum : 상수 필드

    USER("USER"),
    ADMIN("ADMIN"),
    ALL("USER,ADMIN");

    private String role;

    OhgiraffersRole(String role) {
        this.role = role;
    }

    public String getRole() {
        return role;
    }
}

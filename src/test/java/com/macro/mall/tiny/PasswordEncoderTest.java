package com.macro.mall.tiny;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @Author songbo
 * @Date 2022/3/23 13:24
 * @Version 1.0
 */
public class PasswordEncoderTest {
    public static void main(String[] args) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        System.out.println(passwordEncoder.encode("123456"));
        System.out.println(passwordEncoder.matches("123456", "$2a$10$N2grsbOf28Zu/xmw8j2B0eWFZXufpLj7.zyjRkYHly3iwybF8fYVC"));
    }
}

package com.example.demo.web.controller;

import com.example.demo.web.constant.AppConstants;
import io.jsonwebtoken.Jwts;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import java.nio.charset.StandardCharsets;

/**
 * @author olic
 * @date 2023/6/900:42
 */
@RestController
@RequestMapping("/user")
public class UserController {

    /**
     * 获取用户信息
     * @param token
     * @return
     */
    @GetMapping("/getCurrentUserInfo")
    public Object getCurrentUserInfo(@RequestHeader("Authorization") String token) {
        System.out.println("解析token》》》");
        if (!StringUtils.isEmpty(token) && token.startsWith(AppConstants.TOKEN_PREFIX)) {
            token = token.replace(AppConstants.TOKEN_PREFIX, "");
        }
        return Jwts.parser()
                .setSigningKey("test_key".getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();
    }

}

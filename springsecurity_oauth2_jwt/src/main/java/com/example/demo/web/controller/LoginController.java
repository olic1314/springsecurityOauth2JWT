package com.example.demo.web.controller;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

/**
 * @author olic
 * @date 2023/6/1103:13
 */
@RestController
@RequestMapping("/auth")
public class LoginController {
    @Resource
    private AuthenticationManager authenticationManager;

    @GetMapping("/login")
    public Object getCurrentUserInfo() {

        // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername。该过程查询数据库中的LoginUser
        // 该方法会把数据库中查询出的loginUser封装到Authentication，最后再存在security上下文中
        // 使用了security认证流程或手动将权限信息添加到authentication中，在鉴权的时候直接使用security鉴权。如，直接使用@PreAuthorize("hasAuthority('core:abnormalEvent:query')")
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken("lsh", "123456"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        User user = (User)authentication.getPrincipal();

        return "你好";
    }
}



package com.example.demo.web.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.demo.web.domain.UserInfo;
import com.example.demo.web.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 获取用户信息
 * @author olic
 * @date 2023/6/812:57
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserInfoService userInfoService;
//    @Autowired
//    private PasswordEncoder passwordEncoder;

    /**
     * 加载用户信息
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        return User.withUsername(username).password(passwordEncoder.encode("123456")).authorities("p1").build();

        UserInfo userInfo = userInfoService.getBaseMapper().selectOne(new QueryWrapper<UserInfo>().lambda()
                .eq(UserInfo::getUserLogin, username).eq(UserInfo::getStatus, 10001));

//        return LoginUser.builder()
//                .userId(userInfo.getUserId()).username(userInfo.getUserLogin())
//                .username(userInfo.getUserLogin())
//                .user(userInfo).password(userInfo.getPassword()).roles(Arrays.asList("TAG")).build();

        return User.withUsername(username).password(userInfo.getPassword()).authorities("role").build();
    }
}

package com.example.demo.web.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.demo.web.mapper.UserInfoMapper;
import com.example.demo.web.domain.UserInfo;
import com.example.demo.web.service.UserInfoService;
import org.springframework.stereotype.Service;

/**
 * 用户信息表 服务实现类
 */
@Service
public class UserInfoServiceImpl extends ServiceImpl<UserInfoMapper, UserInfo> implements UserInfoService {

}



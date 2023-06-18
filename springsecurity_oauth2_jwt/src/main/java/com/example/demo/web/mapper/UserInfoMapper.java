package com.example.demo.web.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.demo.web.domain.UserInfo;
import org.apache.ibatis.annotations.Mapper;

/**
 * @author olic
 * @date 2023/6/1222:56
 */
@Mapper
public interface UserInfoMapper extends BaseMapper<UserInfo> {
}

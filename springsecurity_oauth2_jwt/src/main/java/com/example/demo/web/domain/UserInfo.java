package com.example.demo.web.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import java.io.Serializable;
import java.util.Date;

/**
 * 用户信息
 * @author olic
 * @date 2023/6/1222:36
 */
@Data
@TableName("T_USER_INFO")
public class UserInfo implements Serializable {

    @TableId(value = "USER_ID", type = IdType.AUTO)
    private Integer userId;

    @TableField("USER_TYPE")
    private Integer userType;

    @TableField("USER_NAME")
    private String userName;

    @TableField("USER_ICON")
    private String userIcon;

    @TableField("USER_LOGIN")
    private String userLogin;

    @TableField("`PASSWORD`")
    private String password;

    @TableField("`STATUS`")
    private Integer status;

    @TableField("CREATE_TIME")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss",timezone = "GMT+8")
    private Date createTime;

    @TableField("DELETE_STATUS")
    private Integer deleteStatus;

    @TableField("UPDATE_TIME")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss",timezone = "GMT+8")
    private Date updateTime;

    @TableField("BIND_SYSTEM_COUNT")
    private Integer bindSystemCount;

    @TableField("BIND_IOC_COUNT")
    private Integer bindIocCount;

    @TableField("ROLE_NAME")
    private String roleName;
}


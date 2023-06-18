//package com.example.demo.web.domain;
//
//import com.fasterxml.jackson.annotation.JsonIgnore;
//import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
//import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
//import lombok.Builder;
//import lombok.Data;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import java.io.Serializable;
//import java.util.*;
//
///**
// * 登录用户
// * 在序列化和反序列化期间，Jackson 将检查每个字段是否存在，并尝试从序列化数据中读取它们。如果找不到某些字段，则会引发异常
// * @JsonIgnoreProperties 该注解将忽略那些在JSON数据中存在但在类中不存在的字段
// * @author olic
// * @date 2023/6/1220:02
// */
//@Data
//@Builder
//@JsonIgnoreProperties(ignoreUnknown = true )
//public class LoginUser implements UserDetails, Serializable {
//    private static final long serialVersionUID = 1L;
//
//    /**
//     * 用户名id
//     */
//    private Integer userId;
//
//    /**
//     * 用户名
//     */
//    private String username;
//
//    /**
//     *
//     */
//    @JsonIgnore
//    private String password;
//
//    /**
//     * 权限列表
//     */
//    private Set<String> permissions;
//
//    /**
//     * 角色列表
//     */
//    private List<String> roles;
//
//    /**
//     * 用户信息
//     */
//    private UserInfo user;
//
////    @TableField(exist = false)
////    private Collection<? extends GrantedAuthority> authorities;
//
////    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
////        this.authorities = authorities;
////    }
////    @Override
////    @JsonIgnore
////    public Collection<? extends GrantedAuthority> getAuthorities() {
////        return Collections.emptyList();
////    }
//
//    @JsonIgnore
//    @Override
//    public String getPassword() {
//        return user.getPassword();
//    }
//
//    @Override
//    public String getUsername() {
//        return user.getUserLogin();
//    }
//
//    /**
//     * 账户是否未过期, 过期不能身份验证（true账号没过期，false账号过期）
//     */
//    @Override
//    public boolean isAccountNonExpired() {
//        return true;
//    }
//
//    /**
//     * 账号是否被锁定锁住状态，锁定状态不能身份验证（true账号没有锁住，false账号锁住）
//     * @return
//     */
//    @Override
//    public boolean isAccountNonLocked() {
//        return true;
//    }
//
//    /**
//     * 过期的凭据防止认证，过期的凭据不能身份验证（true为过期，false过期）
//     * @return
//     */
//    @Override
//    public boolean isCredentialsNonExpired() {
//        return true;
//    }
//
//    /**
//     * 是否可用，禁用的用户不能身份验证（true账号可用，false账号不可用）
//     */
//    @Override
//    public boolean isEnabled() {
//        return true;
//    }
//}
//

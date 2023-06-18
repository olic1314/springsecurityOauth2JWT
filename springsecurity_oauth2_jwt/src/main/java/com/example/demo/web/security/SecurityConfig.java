package com.example.demo.web.security;

import com.example.demo.web.handle.AuthenticationEntryPointImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * security相关配置
 * @author olic
 * @date 2023/6/811:54
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationEntryPointImpl authenticationEntryPoint;

    /*
     * 重新实例化bean
     * @return
     * @throws Exception
     */
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * security相关配置
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
         http.authorizeRequests()
                .antMatchers(oAuthUri)
                .permitAll()
                .anyRequest().authenticated()
                 .and()
                 // 认证失败处理类
                 .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint)
                 .and()
                .formLogin()
                .permitAll()
                .and()
                .httpBasic()
                .and()
                .csrf().disable();
    }

    String[] oAuthUri = {
            "/auth/login",
            "/oauth/token",
            "/oauth/check_token",
            "/user/**"
    };
}

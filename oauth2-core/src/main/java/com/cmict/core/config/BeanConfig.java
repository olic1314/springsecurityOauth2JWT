package com.cmict.core.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import javax.sql.DataSource;

/**
 * security相关配置
 * @author olic
 * @date 2023/6/811:54
 */
@Configuration
@EnableWebSecurity
public class BeanConfig{

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * 配置jwtToken
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new CustomJwtAccessTokenConverter();
        //添加认证JwtToken的密钥
        jwtAccessTokenConverter.setSigningKey("test_key");
        return jwtAccessTokenConverter;
    }

//    /**
//     * 配置认证管理器 -- 内存形式
//     * @return
//     * @throws Exception
//     */
//    @Bean
//    public AuthorizationCodeServices authorizationCodeServices() throws Exception {
//        return new InMemoryAuthorizationCodeServices();
//    }

    /**
     * 配置认证管理器-数据源形式
     * @return
     * @throws Exception
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(DataSource dataSource) throws Exception {
        return new JdbcAuthorizationCodeServices(dataSource);
    }

//    /**
//     * 重新实例化bean
//     * @return
//     * @throws Exception
//     */
//    @Bean
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }


    /**
     * 客户端身份校验-数据源形式
     * @param dataSource
     * @return
     */
    @Bean
    public ClientDetailsService clientDetailsService(DataSource dataSource){
        JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        clientDetailsService.setPasswordEncoder(passwordEncoder);
        return clientDetailsService;
    }

//    /**
//     * 身份认证配置
//     * @param auth
//     * @throws Exception
//     */
//    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
////        auth.inMemoryAuthentication().withUser("lsh").password(passwordEncoder.encode("123456"));
//    }

//    /**
//     * security相关配置
//     * @param http
//     * @throws Exception
//     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/oauth/**","/login/**", "/logout/**","/user/**","/auth/login")
//                .permitAll()
//                .anyRequest().authenticated()
//                .and()
//                // 认证失败处理类
////                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint)
////                .and()
//                .formLogin()
//                .permitAll()
//                .and()
//                .httpBasic()
//                .and()
//                .csrf().disable();
//    }
}

package com.cmict.core.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import java.util.ArrayList;
import java.util.List;

/**
 * 授权服务器配置
 * @author olic
 * @date 2023/6/811:26
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    @Autowired
    private ClientDetailsService clientDetailsService;

    /**
     * 配置令牌端点的安全策略
     *
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security// /oauth/token_key 公开
                .tokenKeyAccess("permitAll()")
                // /oauth/check_token公开
                .checkTokenAccess("permitAll()")
                // 表单验证(申请令牌)
                .allowFormAuthenticationForClients();
    }

    /**
     * 客户端身份校验
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //配置数据源形式
        clients.withClientDetails(clientDetailsService);
//        //内存配置形式
//        clients.inMemory()
//                //配置client Id
//                .withClient("admin_client_id")
//                //配置client-secret
//                .secret(passwordEncoder.encode("112233"))
//                //配置重定向的跳转，用于授权成功之后的跳转
//                .redirectUris("http://www.baidu.com")
//                //作用域
//                .scopes("all")
//                //不用跳转授权页面直接发code
//                .autoApprove(true)
//                //Grant_type 授权码模式。refresh_token: 可以使用refresh_token刷新access_token的过期时间，refreshToken可以提高安全性
//                .authorizedGrantTypes("authorization_code", "password", "refresh_token");
    }

    /**
     * 配置令牌服务
     *
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        //配置Jwt内容增强器
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> delegates = new ArrayList<>();
        delegates.add(jwtAccessTokenConverter);
        tokenEnhancerChain.setTokenEnhancers(delegates);
        endpoints.authenticationManager(authenticationManager)
                //授权码模式
                .authorizationCodeServices(authorizationCodeServices)
                .tokenEnhancer(tokenEnhancerChain);
    }
}
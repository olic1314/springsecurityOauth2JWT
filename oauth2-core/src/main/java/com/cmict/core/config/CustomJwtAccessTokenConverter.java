package com.cmict.core.config;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.Date;

/**
 * 增强JWTToken
 * @author olic
 * @date 2023/6/1301:30
 */
@Component
public class CustomJwtAccessTokenConverter extends JwtAccessTokenConverter {
    private static final int ACCESS_TOKEN_VALIDITY_SECONDS = 60 * 5; // Access Token 有效期为5分钟

    /**
     * token设置
     * @param accessToken
     * @param authentication
     * @return
     */
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(super.enhance(accessToken, authentication));
        result.setExpiration(Date.from(Instant.now().plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS)));
        return result;
    }
}

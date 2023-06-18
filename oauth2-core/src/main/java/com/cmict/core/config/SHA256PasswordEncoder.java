package com.cmict.core.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 密码管理器。用于客户端security加密和用户账号密码加密
 * @author olic
 * @date 2023/6/1017:25
 */
@Slf4j
@Configuration
public class SHA256PasswordEncoder implements PasswordEncoder {
    private static final String SALT = "onearcsalt";

    /**
     * 加密
     * @param charSequence
     * @return
     */
    @Override
    public String encode(CharSequence charSequence) {
        String str = charSequence.toString();
        Integer saltIndex = SALT.length() % str.length();
        String saltStr = SALT.substring(0,saltIndex);
        StringBuffer sha256StrBuffer = new StringBuffer();
        sha256StrBuffer.append(str.substring(0,saltIndex));
        sha256StrBuffer.append(saltStr);
        sha256StrBuffer.append(str.substring(saltIndex));
        String sha256Str = sha256StrBuffer.toString();
        return getSha256(sha256Str);
    }

    /**
     * 密码匹配
     * @param rawPassword
     * @param encodedPassword
     * @return
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encode(rawPassword.toString()).equals(encodedPassword);
    }

    /**
     * SHA256加密
     * @param str
     * @return
     */
    public static String getSha256(String str){
        MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes("UTF-8"));
            encodeStr = byte2Hex(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        log.info("SHA256Str:{}", encodeStr);
        return encodeStr;
    }

    /**
     * 将byte转为16进制
     * @param bytes
     * @return
     */
    private static String byte2Hex(byte[] bytes){
        StringBuffer stringBuffer = new StringBuffer();
        String temp = null;
        for (int i=0;i<bytes.length;i++){
            temp = Integer.toHexString(bytes[i] & 0xFF);
            if (temp.length()==1){
                //1得到一位的进行补0操作
                stringBuffer.append("0");
            }
            stringBuffer.append(temp);
        }
        return stringBuffer.toString();
    }
}

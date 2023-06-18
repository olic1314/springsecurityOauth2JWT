package com.example.demo.web.utils;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author olic
 * @date 2023/6/1017:24
 */
public class Sha256Util {
    private static final String SALT = "onearcsalt";
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
        return encodeStr;
    }

    public static String getSha256WithSalt(String str){
        Integer saltIndex = SALT.length() % str.length();
        String saltStr = SALT.substring(0,saltIndex);
        StringBuffer sha256StrBuffer = new StringBuffer();
        sha256StrBuffer.append(str.substring(0,saltIndex));
        sha256StrBuffer.append(saltStr);
        sha256StrBuffer.append(str.substring(saltIndex));
        String sha256Str = sha256StrBuffer.toString();
//         System.out.println("sha256Str is " + sha256Str);
        return getSha256(sha256Str);

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

    /**
     * 使用SHA256 对两端加密后的密文进行比较
     *
     * @param strOne
     *            未加密的字符串
     * @param strTwo
     *            已加密的字符串
     * @return boolean
     */
    public static boolean check(String strOne, String strTwo) {
        if (getSha256(strOne).equals(strTwo))
            return true;
        else
            return false;
    }

    public static void main(String[] args) {
        String sha256WithSalt = getSha256WithSalt("123456abc!@#");
        System.out.println(sha256WithSalt);
    }
}

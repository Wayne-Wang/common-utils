package com.wayne.utils;

import org.apache.commons.lang3.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @Author Wayne.Wang
 * @Date 18/9/18
 */
public class Md5Utils {

    /**
     * @param str
     * @return
     * @Description:  32位小写MD5
     */
    public static String plainToMd5L32(String str)  {
        if(StringUtils.isEmpty(str)){
            return null;
        }
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5算法异常",e);
        }
        byte[] bytes = md5.digest(str.getBytes());
        StringBuffer stringBuffer = new StringBuffer();
        for (byte b : bytes){
            int bt = b&0xff;
            if (bt < 16){
                stringBuffer.append(0);
            }
            stringBuffer.append(Integer.toHexString(bt));
        }
        return stringBuffer.toString();
    }

    /**
     * @param str
     * @return
     * @Description: 32位大写MD5
     */
    public static String plainToMd5U32(String str)  {
        String reStr = plainToMd5L32(str);
        if (reStr != null){
            reStr = reStr.toUpperCase();
        }
        return reStr;
    }

    /**
     * @param str
     * @Description: 16位大写MD5
     */
    public static String plainToMd5U16(String str)  {
        String reStr = plainToMd5L32(str);
        if (reStr != null){
            reStr = reStr.toUpperCase().substring(8, 24);
        }
        return reStr;
    }

    /**
     * @param str
     * @return
     * @Description: 16位小写MD5
     */
    public static String plainToMd5L16(String str)  {
        String reStr = plainToMd5L32(str);
        if (reStr != null){
            reStr = reStr.substring(8, 24);
        }
        return reStr;
    }
}

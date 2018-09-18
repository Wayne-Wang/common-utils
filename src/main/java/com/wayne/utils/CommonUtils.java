package com.wayne.utils;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;

/**
 * @Author Wayne.Wang
 * @Date 18/9/18
 */
public class CommonUtils {
    private static final Logger logger = LoggerFactory.getLogger(CommonUtils.class);

    /**
     * 取得字符串UTF-8编码字节数组.
     * @param str
     * @return
     */
    public static byte[] getUTF8Bytes(String str) {
        try {
            return str.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            logger.error("字符串转换UTF-8编码集异常", e);
            throw new RuntimeException(e);
        }
    }
}

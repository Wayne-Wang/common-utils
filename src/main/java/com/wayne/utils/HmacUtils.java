package com.wayne.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.misc.BASE64Encoder;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * HMC加密
 * @Author Wayne.Wang
 * @Date 18/9/18
 */
public class HmacUtils {
    private static final Logger logger = LoggerFactory.getLogger(HmacUtils.class);
    private static final String HMAC_PUBLIC_KEY = "";

    /**
     * MAC算法可选以下多种算法
     *
     * <pre>
     * HmacMD5
     * HmacSHA1
     * HmacSHA256
     * HmacSHA384
     * HmacSHA512
     * </pre>
     */
    public static final String KEY_MAC = "HmacMD5";

    /**
     * 对字符串str进行HAMC加密
     * @param str
     * @return
     */
    public static String hmac(String str) {
        // 变成hmac
        Mac mac = getMac(HMAC_PUBLIC_KEY);
        byte[] ret = mac.doFinal(CommonUtils.getUTF8Bytes(str));
        String hmac = DatatypeConverter.printBase64Binary(ret);
        return hmac;
    }

    /**
     * 获取Mac实例
     * @param hmacKey
     * @return
     */
    private static Mac getMac(String hmacKey) {
        try {
            SecretKey secretKey = new SecretKeySpec(DatatypeConverter.parseBase64Binary(hmacKey), KEY_MAC);

            Mac mac = Mac.getInstance(secretKey.getAlgorithm());
            mac.init(secretKey);
            return mac;
        } catch (NoSuchAlgorithmException ex) {
            logger.error("获取加密实例异常, HMAC无此算法", ex);
            throw new RuntimeException(ex);
        } catch (InvalidKeyException ex) {
            logger.error("获取加密实例异常, HMAC无效的密钥", ex);
            throw new RuntimeException(ex);
        }
    }

    /**
     * 使用HMAC的其他算法加密
     * @param str
     * @param algorithm
     * @return
     */
    public static String hmac(String str, String algorithm) {
        Mac mac = getMac(HMAC_PUBLIC_KEY, algorithm);
        byte[] ret = mac.doFinal(CommonUtils.getUTF8Bytes(str));
        return DatatypeConverter.printBase64Binary(ret);
    }

    /**
     * 获取HMAC其他算法的MAC实例
     * @param hmacKey
     * @param algorithm
     * @return
     */
    private static Mac getMac(String hmacKey, String algorithm) {
        try {
            SecretKey secretKey = new SecretKeySpec(DatatypeConverter.parseBase64Binary(hmacKey), algorithm);

            Mac mac = Mac.getInstance(secretKey.getAlgorithm());
            mac.init(secretKey);
            return mac;
        } catch (NoSuchAlgorithmException ex) {
            logger.error("获取加密实例异常, HMAC无此算法", ex);
            throw new RuntimeException(ex);
        } catch (InvalidKeyException ex) {
            logger.error("获取加密实例异常, HMAC无效的密钥", ex);
            throw new RuntimeException(ex);
        }
    }

    /**
     * 生成HMAC加密的密钥
     * @return
     */
    public static String init() {
        SecretKey key;
        String str = "";
        try {
            KeyGenerator generator = KeyGenerator.getInstance(KEY_MAC);
            key = generator.generateKey();
            str = encryptBase64(key.getEncoded());
            return str;
        } catch (Exception e) {
            throw new RuntimeException("生成key失败");
        }
    }

    /**
     * 二进制数据通过base64转码
     * @param encoded
     * @return
     */
    private static String encryptBase64(byte[] encoded) {
        return (new BASE64Encoder()).encodeBuffer(encoded);
    }

    public static void main(String[] args) throws Exception {
        String s = UUID.randomUUID().toString();
        String appCode = s.substring(0, 8) + s.substring(9, 13)
                + s.substring(14, 18) + s.substring(19, 23) + s.substring(24);
        System.out.println("生成的appCode为：" + appCode.toUpperCase());
        String pubKey = init().replaceAll("\r|\n", "");
        System.out.println("生成的key为：" + pubKey);
    }
}

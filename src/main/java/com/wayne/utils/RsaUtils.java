package com.wayne.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Rsa非对称加密
 * @Author Wayne.Wang
 * @Date 18/9/18
 */
public class RsaUtils {
    private static final Logger logger = LoggerFactory.getLogger(RsaUtils.class);
    public static final String SIGN_ALGORITHMS = "SHA1WithRSA";
    private static final String ALGORITHM = "Rsa";

    /**
     * RSA签名
     * @param content    待签名数据
     * @param privateKey 商户私钥
     * @param charset    编码格式
     * @return 签名值
     */
    public static String sign(String content, String privateKey, String charset) {
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
            KeyFactory keyf = KeyFactory.getInstance(ALGORITHM);
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);
            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
            signature.initSign(priKey);
            signature.update(content.getBytes(charset));
            byte[] signed = signature.sign();
            return Base64.encodeBase64String(signed);
        } catch (Exception e) {
            logger.error("RSA加密数据异常:", e);
            throw new RuntimeException("RSA加密数据失败");
        }
    }

    /**
     * RSA验签名检查
     * @param content   待签名数据
     * @param sign      签名值
     * @param publicKey 公钥
     * @param charset   编码格式
     * @return 布尔值
     */
    public static boolean verify(String content, String sign, String publicKey, String charset) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            byte[] encodedKey = Base64.decodeBase64(publicKey);
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
            signature.initVerify(pubKey);
            signature.update(content.getBytes(charset));
            return signature.verify(Base64.decodeBase64(sign));
        } catch (Exception e) {
            logger.error("RSA数据验签名异常:", e);
            return false;
        }
    }

    /**
     * 公钥加密过程
     * @param publicKey     公钥
     * @param plainTextData 明文数据
     * @return
     * @throws Exception 加密过程中的异常信息
     */
    public static byte[] encrypt(String publicKey, byte[] plainTextData) throws Exception {
        if (StringUtils.isBlank(publicKey)) {
            throw new Exception("加密公钥为空, 请设置");
        }
        RSAPublicKey rsaPublicKey = loadPublicKeyByStr(publicKey);
        Cipher cipher = null;
        try {
            // 使用默认RSA
            cipher = Cipher.getInstance("Rsa");
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            byte[] output = cipher.doFinal(plainTextData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {
            throw new Exception("无此填充机制");
        } catch (InvalidKeyException e) {
            throw new Exception("加密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("明文数据已损坏");
        }
    }

    /**
     * 从字符串中加载公钥
     * @param publicKeyStr 公钥数据字符串
     * @throws Exception 加载公钥时产生的异常
     */
    public static RSAPublicKey loadPublicKeyByStr(String publicKeyStr)
            throws Exception {
        try {
            byte[] buffer = Base64.decodeBase64(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("Rsa");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        } catch (NullPointerException e) {
            throw new Exception("公钥数据为空");
        }
    }

    /**
     * 解密
     * @param content       密文
     * @param privateKey   商户私钥
     * @param charset 编码格式
     * @return 解密后的字符串
     */
    public static String decrypt(String content, String privateKey, String charset) throws Exception {
        PrivateKey prikey = getPrivateKey(privateKey);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, prikey);
        InputStream ins = new ByteArrayInputStream(Base64.decodeBase64(content));
        ByteArrayOutputStream writer = new ByteArrayOutputStream();
        //rsa解密的字节大小最多是128，将需要解密的内容，按128位拆开解密
        byte[] buf = new byte[128];
        int length;
        while ((length = ins.read(buf)) != -1) {
            byte[] block = null;
            if (buf.length == length) {
                block = buf;
            } else {
                block = new byte[length];
                for (int i = 0; i < length; i++) {
                    block[i] = buf[i];
                }
            }
            writer.write(cipher.doFinal(block));
        }
        return new String(writer.toByteArray(), charset);
    }

    /**
     * 解密二进制数据
     * @param privateKey
     * @param cipherData
     * @return 返回解密后的二进制数据
     * @throws Exception
     */
    public static byte[] decrypt(String privateKey, byte[] cipherData) throws Exception {
        if (StringUtils.isBlank(privateKey)) {
            throw new Exception("解密私钥为空, 请设置");
        }
        PrivateKey rsaPrivateKey = getPrivateKey(privateKey);
        Cipher cipher = null;
        try {
            // 使用默认RSA
            cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            byte[] output = cipher.doFinal(cipherData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            throw new Exception("无此填充机制");
        } catch (InvalidKeyException e) {
            throw new Exception("解密私钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        }
    }

    /**
     * 得到私钥
     * @param key 密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }
}

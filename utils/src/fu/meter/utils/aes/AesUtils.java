package fu.meter.utils.aes;

import fu.meter.utils.common.Base64Util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @ClassName:AesUtils
 * @author:meter
 * @date:2019/6/24 18:02
 * @desc:aes加密解密工具
 *  1、生成合适的长度的秘钥和偏移量；
 *  2、
 * @version:1.0
 * @copyright:All Rights Reserved @2019
 */
public class AesUtils {
    /**
     * 加密类型Aes
     */
    private static final String AES = "AES";
    /**
     * 填充方式：对于加密解密两端需要使用同一的PADDING模式，大部分PADDING模式为PKCS5, PKCS7, NOPADDING
     */
    private static final String PADDING_TYPE = "AES/CBC/PKCS5Padding";
    /**
     * 生成AES密钥, 默认长度为256位(32字节).可选长度为128,192,256位.
     */
    private static final int DEFAULT_KEYSIZE = 32;
    /**
     * 生成随机向量, 默认大小为cipher.getBlockSize(), 16字节
     */
    private static final int DEFAULT_IVSIZE = 16;
    /**
     * 默认编码
     */
    private static final String DEFAULT_ENCODING = "UTF-8";
    /**
     * 偏移量不足位数时补齐字符
     */
    private static final byte OFFSET_IV = 0;
    /**
     * 秘钥不足位数时补齐字符
     */
    private static final byte OFFSET_KEY = 1;

    /**
     * @return byte[]
     * @desc 生成随机向量, 默认大小为, 16字节.
     * @author meter
     * @date 2019/6/25 9:26
     */
    public static byte[] genRandomIV() {
        byte[] bytes = new byte[DEFAULT_IVSIZE];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    /**
     * @param iv
     * @return byte[]
     * @desc 根据SecureRandom生成偏移量
     * @author meter
     * @date 2019/6/14 17:17
     */
    public static byte[] genIV(String iv) throws UnsupportedEncodingException {
        byte[] bytes = new byte[DEFAULT_IVSIZE];
        new SecureRandom(iv.getBytes(DEFAULT_ENCODING)).nextBytes(bytes);
        return bytes;
    }


    /**
     * @param input 原始字节数组
     * @param key   符合AES要求的密钥:DEFAULT_AES_KEYSIZE大小的秘钥
     * @param iv    初始向量：DEFAULT_IVSIZE大小的偏移量
     * @param mode  Cipher.ENCRYPT_MODE 或 Cipher.DECRYPT_MODE
     * @desc 使用AES加密或解密无编码的原始字节数组, 返回无编码的字节数组结果.带偏移量
     * @author meter
     */
    private static byte[] aes(byte[] input, byte[] key, byte[] iv, int mode) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, AES);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(PADDING_TYPE);
            cipher.init(mode, secretKey, ivSpec);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param input 原始字节数组
     * @param key   符合AES要求的密钥:DEFAULT_KEYSIZE大小的key
     * @param mode  Cipher.ENCRYPT_MODE 或 Cipher.DECRYPT_MODE
     * @desc 使用AES加密或解密无编码的原始字节数组, 返回无编码的字节数组结果.不带偏移量
     * @author meter
     */
    private static byte[] aes(byte[] input, byte[] key, int mode) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, AES);
            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(mode, secretKey);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param data 加密数据
     * @param key  加密秘钥
     * @return byte[] 返回加密后字节数据
     * @desc aes加密字节数组(不带偏移量)
     * @author meter
     * @date 2019/6/25 9:37
     */
    public static byte[] encode(byte[] data, byte[] key) {
        key = checkKeyLength(key);
        return aes(data, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * @param data 加密数据
     * @param key  加密秘钥
     * @param iv   偏移量
     * @return byte[] 返回加密后字节数据
     * @desc aes加密字节数组(带偏移量)
     * @author meter
     * @date 2019/6/25 9:37
     */
    public static byte[] encode(byte[] data, byte[] key, byte[] iv) {
        key = checkKeyLength(key);
        iv = checkIvLength(iv);
        return aes(data, key, iv, Cipher.ENCRYPT_MODE);
    }

    /**
     * @param data     待加密数据
     * @param password 秘钥
     * @return  加密后字符串数据
     * @desc aes加密字符串数据(不带偏移量)
     * @author meter
     * @date 2019/6/25 10:41
     */
    public static String encodeToString(String data, String password) throws UnsupportedEncodingException {
        byte[] arrData= encode(data.getBytes(DEFAULT_ENCODING), password.getBytes(DEFAULT_ENCODING));
        return Base64Util.encodeToString(arrData);
    }

    /**
     * @param data     待加密数据
     * @param password 秘钥
     * @param iv       偏移量
     * @return 加密后字符串数据
     * @desc aes加密字符串数据(带偏移量)
     * @author meter
     * @date 2019/6/25 10:41
     */
    public static String encodeToString(String data, String password, String iv) throws UnsupportedEncodingException {
        byte[] arrData= encode(data.getBytes(DEFAULT_ENCODING), password.getBytes(DEFAULT_ENCODING), iv.getBytes(DEFAULT_ENCODING));
        return Base64Util.encodeToString(arrData);
    }

    /**
     * @param data 加密过的数据
     * @param key  解密秘钥
     * @return byte[] 解密后字节数据
     * @desc 解密字节数组(不带偏移量)
     * @author meter
     * @date 2019/6/25 10:45
     */
    public static byte[] decode(byte[] data, byte[] key) {
        key = checkKeyLength(key);
        return aes(data, key, Cipher.DECRYPT_MODE);
    }

    /**
     * @param data 加密过的数据
     * @param key  解密秘钥
     * @param iv   偏移量
     * @return byte[] 解密后字节数据
     * @desc 解密字节数组(带偏移量)
     * @author meter
     * @date 2019/6/25 10:45
     */
    public static byte[] decode(byte[] data, byte[] key, byte[] iv) {
        key = checkKeyLength(key);
        iv = checkIvLength(iv);
        return aes(data, key, iv, Cipher.DECRYPT_MODE);
    }

    /**
     * @param data     aes加密然后base64加密的数据
     * @param password 解密秘钥
     * @return  返回解密后的原文数据
     * @desc 解密字符串数据(不带偏移量)
     * @author meter
     * @date 2019/6/25 10:49
     */
    public static String decodeFromString(String data, String password) throws UnsupportedEncodingException {
        byte[] arrData= Base64Util.decodeFromString(data);
        return new String(decode(arrData, password.getBytes(DEFAULT_ENCODING)),DEFAULT_ENCODING);
    }

    /**
     * @param data     aes加密然后base64加密数据
     * @param password 解密秘钥
     * @param iv       偏移量
     * @return 返回解密后的原文数据
     * @desc 解密字符串数据(带偏移量)
     * @author meter
     * @date 2019/6/25 10:49
     */
    public static String decodeFromString(String data, String password, String iv) throws UnsupportedEncodingException {
        byte[] arrData= Base64Util.decodeFromString(data);
        return new String(decode(arrData, password.getBytes(DEFAULT_ENCODING), iv.getBytes(DEFAULT_ENCODING)),DEFAULT_ENCODING);
    }


    /**
     * @param iv
     * @return void
     * @desc 效验偏移量长度是否符合，不符合则处理为符合规则的长度
     * 大于DEFAULT_IVSIZE的截取到DEFAULT_IVSIZE大小；
     * 小于DEFAULT_IVSIZE的则以OFFSET_IV补齐
     * @author meter
     * @date 2019/6/25 9:40
     */
    private static byte[] checkIvLength(byte[] iv) {
        int ivLength = iv.length;
        if (ivLength == DEFAULT_IVSIZE) {
            return iv;
        } else if (ivLength < DEFAULT_IVSIZE) {
            return fillByteArray(iv, OFFSET_IV, DEFAULT_IVSIZE);
        } else {
            byte[] result = new byte[DEFAULT_IVSIZE];
            System.arraycopy(iv, 0, result, 0, DEFAULT_IVSIZE);
            return result;
        }
    }

    /**
     * @param key
     * @return void
     * @desc 效验秘钥长度，处理为符合长度
     * 大于DEFAULT_KEYSIZE的截取到DEFAULT_KEYSIZE大小；
     * 小于DEFAULT_KEYSIZE的则以OFFSET_KEY补齐
     * @author meter
     * @date 2019/6/25 9:41
     */
    private static byte[] checkKeyLength(byte[] key) {
        int keyLength = key.length;
        if (keyLength == DEFAULT_KEYSIZE) {
            return key;
        } else if (keyLength < DEFAULT_KEYSIZE) {
            return fillByteArray(key, OFFSET_KEY, DEFAULT_KEYSIZE);
        } else {
            byte[] subArr = new byte[DEFAULT_KEYSIZE];
            System.arraycopy(key, 0, subArr, 0, DEFAULT_KEYSIZE);
            return subArr;
        }
    }

    /**
     * @param arr  原数据
     * @param b    填充数据
     * @param size 填充后大小
     * @return byte[]
     * @desc 填充字节数组到指定大小
     * @author meter
     * @date 2019/6/25 10:17
     */
    private static byte[] fillByteArray(byte[] arr, byte b, int size) {
        byte[] result = new byte[size];
        System.arraycopy(arr, 0, result, 0, arr.length);
        for (int i = arr.length; i < size; i++) {
            result[i] = b;
        }
        return result;
    }
    /**
     * @desc  生成AES密钥,
     * @param keysize 可选长度为128,192,256位.	
     * @param password	
     * @return byte[]
     * @author meter
     * @date 2019/6/25 14:06
    */
    public static byte[] genRandomAesKey(int keysize, String password) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(keysize, new SecureRandom(password.getBytes()));
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * @desc 生成默认位数长度秘钥
     * @param password	
     * @return byte[]
     * @author meter
     * @date 2019/6/25 14:07
    */
    public static byte[] genRandomAesKey(String password) throws NoSuchAlgorithmException {
        return genRandomAesKey(DEFAULT_KEYSIZE*8, password);
    }

    //--------------------------------米特华丽的分割线[setter区域]-------------------------------------------------------




    //--------------------------------米特华丽的分割线[测试区域]-------------------------------------------------------

    /**
     * @author meter
     * @desc 测试方法
     */
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        String data="This is a aes data.Please encrypted it.";
        String password="password123";
        String iv="pianyiliang123";
         String arr= encodeToString(data,password);
        System.out.println(new String(arr));
        arr=decodeFromString(arr,password);
        System.out.println((arr));
        System.out.println("-----------------------------");
        arr= encodeToString(data,password,iv);
        System.out.println((arr));
        arr=decodeFromString(arr,password,iv);
        System.out.println((arr));
        System.out.println(new String(genRandomAesKey(password)));
    }

}

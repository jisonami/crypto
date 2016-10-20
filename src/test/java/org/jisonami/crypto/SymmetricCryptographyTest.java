package org.jisonami.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Security;

/**
 * Created by jisonami on 2016/9/30.
 */
public class SymmetricCryptographyTest {

    private static final String data = "明文数据test中文";

    /**
     * 测试使用默认的AES对称加密算法进行加密解密
     */
    @Test
    public void testAESCrypto() {
        SymmetricCryptography symmetricCryptography = new SymmetricCryptography();
        String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
        System.out.println("AES密钥：" + key);
        String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
        System.out.println("解密后数据：" + decryptData);
    }

    /**
     * 测试使用默认的AES对称加密算法进行加密解密
     */
    @Test
    public void testAES256Crypto() {
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.AES).setCipherAlgorithm(Algorithms.AES_ECB_PKCS5PADDING).setKeySize(256);
        SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
        String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
        System.out.println("AES密钥：" + key);
        String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
        System.out.println("解密后数据：" + decryptData);
    }

    /**
     * 测试使用DES对称加密算法进行加密解密
     */
    @Test
    public void testDESCrypto() {
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.DES).setCipherAlgorithm(Algorithms.DES_ECB_PKCS5PADDING).setKeySize(56);
        SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
        String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
        System.out.println("DES密钥：" + key);
        String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
        System.out.println("解密后数据：" + decryptData);
    }

    /**
     * 测试使用DESede对称加密算法进行加密解密
     */
    @Test
    public void testDESedeCrypto() {
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.DESEDE).setCipherAlgorithm(Algorithms.DESEDE_ECB_PKCS5PADDING).setKeySize(168);
        SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
        String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
        System.out.println("DESede密钥：" + key);
        String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
        System.out.println("解密后数据：" + decryptData);
    }

    /**
     * 测试使用Blowfish对称加密算法进行加密解密
     */
    @Test
    public void testBlowfishCrypto() {
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.BLOWFISH).setCipherAlgorithm(Algorithms.BLOWFISH_ECB_PKCS5PADDING).setKeySize(128);
        SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
        String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
        System.out.println("Blowfish密钥：" + key);
        String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
        System.out.println("解密后数据：" + decryptData);
    }

    /**
     * 测试使用RC2对称加密算法进行加密解密
     */
    @Test
    public void testRC2Crypto() {
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.RC2).setCipherAlgorithm(Algorithms.RC2).setKeySize(128);
        SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
        String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
        System.out.println("RC2密钥：" + key);
        String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
        System.out.println("解密后数据：" + decryptData);
    }

    /**
     * 测试使用RC4对称加密算法进行加密解密
     */
    @Test
    public void testRC4Crypto() {
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.RC4).setCipherAlgorithm(Algorithms.RC4).setKeySize(128);
        SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
        String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
        System.out.println("RC4密钥：" + key);
        String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
        System.out.println("解密后数据：" + decryptData);
    }

    @Test
    public void testRC4CryptoByBouncyCastle(){
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.RC4).setCipherAlgorithm(Algorithms.RC4).setKeySize(128).setProvider(bouncyCastleProvider);
        SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
        String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
        System.out.println("RC4密钥：" + key);
        String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
        System.out.println("解密后数据：" + decryptData);
    }

    @Test
    public void testIDEACryptoByBouncyCastle(){
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.IDEA).setCipherAlgorithm(Algorithms.IDEA).setKeySize(128).setProvider(bouncyCastleProvider);
        SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
        String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
        System.out.println("RC4密钥：" + key);
        String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
        System.out.println("解密后数据：" + decryptData);
    }

}

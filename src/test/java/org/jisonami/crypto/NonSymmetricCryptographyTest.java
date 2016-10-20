package org.jisonami.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Key;
import java.security.Security;
import java.util.Map;

/**
 * Created by jisonami on 16-10-15.
 */
public class NonSymmetricCryptographyTest {

    private static final String data = "明文数据test中文";

    /**
     * 测试使用RSA非对称加密算法进行加密解密
     */
    @Test
    public void testRSACrypto() {
        NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography();
        Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
        String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
        String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
        System.out.println("RSA私钥：" + privateKey);
        System.out.println("RSA公钥：" + publicKey);
        System.out.println("加密前数据：" + data);
        // 公钥加密私钥解密
        String encryptData = nonSymmetricCryptography.encryptByPublicKey(data, nonSymmetricCryptography.decodeKey(publicKey));
        System.out.println("公钥加密后数据：" + encryptData);
        String decryptData = nonSymmetricCryptography.decryptByPrivateKey(encryptData, nonSymmetricCryptography.decodeKey(privateKey));
        System.out.println("私钥解密后数据：" + decryptData);
        // 私钥加密公钥解密
        String encryptData1 = nonSymmetricCryptography.encryptByPrivateKey(data, nonSymmetricCryptography.decodeKey(privateKey));
        System.out.println("公钥加密后数据：" + encryptData1);
        String decryptData1 = nonSymmetricCryptography.decryptByPublicKey(encryptData1, nonSymmetricCryptography.decodeKey(publicKey));
        System.out.println("私钥解密后数据：" + decryptData1);
    }

    /**
     * ELGAMAL算法只支持公钥加密私钥解密
     */
    @Test
    public void testELGAMALCryptoByBouncyCastle(){
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.ELGAMAL).setCipherAlgorithm(Algorithms.ELGAMAL_ECB_PKCS1PADDING).setKeySize(512).setProvider(bouncyCastleProvider);
        NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography(configuration);
        Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
        String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
        String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
        System.out.println("ELGAMAL私钥：" + privateKey);
        System.out.println("ELGAMAL公钥：" + publicKey);
        System.out.println("加密前数据：" + data);
        // 公钥加密私钥解密
        String encryptData = nonSymmetricCryptography.encryptByPublicKey(data, nonSymmetricCryptography.decodeKey(publicKey));
        System.out.println("公钥加密后数据：" + encryptData);
        String decryptData = nonSymmetricCryptography.decryptByPrivateKey(encryptData, nonSymmetricCryptography.decodeKey(privateKey));
        System.out.println("私钥解密后数据：" + decryptData);
    }

}

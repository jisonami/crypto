package org.jisonami.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Key;
import java.security.Security;
import java.util.Map;

/**
 * Created by jisonami on 16-10-15.
 */
public class KeyAgreementCryptographyTest {

    private static final String data = "明文数据test中文";

    /**
     * 测试使用DH_DES密钥协商算法进行加密解密
     */
    @Test
    public void testDH_DESCrypto() {
        KeyAgreementCryptography keyAgreementCryptography = new KeyAgreementCryptography();
        // 获取甲方密钥对
        Map<String,Key> keyMap = keyAgreementCryptography.initKey();
        String privateKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPrivateKey(keyMap));
        String publicKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPublicKey(keyMap));
        System.out.println("甲方DH私钥：" + privateKey);
        System.out.println("甲方DH公钥：" + publicKey);

        // 获取乙方密钥对
        Map<String,Key> keyMap1 = keyAgreementCryptography.initKey(keyAgreementCryptography.decodeKey(publicKey));
        System.out.println("加密前数据：" + data);
        String privateKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPrivateKey(keyMap1));
        String publicKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPublicKey(keyMap1));
        System.out.println("乙方DH私钥：" + privateKey1);
        System.out.println("乙方DH公钥：" + publicKey1);

        // 获取甲方本地对称密钥
        String secretKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.initSecretKey(keyAgreementCryptography.decodeKey(publicKey1), keyAgreementCryptography.decodeKey(privateKey)));
        System.out.println("甲方本地对称密钥：" + secretKey);

        // 获取乙方本地对称密钥
        String secretKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.initSecretKey(keyAgreementCryptography.decodeKey(publicKey), keyAgreementCryptography.decodeKey(privateKey1)));
        System.out.println("乙方本地对称密钥：" + secretKey1);

        // 甲方加密乙方解密
        String encryptData = keyAgreementCryptography.encrypt(data, keyAgreementCryptography.decodeKey(secretKey));
        System.out.println("甲方加密后数据：" + encryptData);
        String decryptData = keyAgreementCryptography.decrypt(encryptData, keyAgreementCryptography.decodeKey(secretKey1));
        System.out.println("乙方解密后数据：" + decryptData);
        // 乙方加密甲方解密
        String encryptData1 = keyAgreementCryptography.encrypt(data, keyAgreementCryptography.decodeKey(secretKey1));
        System.out.println("乙方加密后数据：" + encryptData1);
        String decryptData1 = keyAgreementCryptography.decrypt(encryptData1, keyAgreementCryptography.decodeKey(secretKey));
        System.out.println("甲方解密后数据：" + decryptData1);
    }

    /**
     * 测试使用DH_DESede密钥协商算法进行加密解密
     */
    @Test
    public void testDH_DESedeCrypto() {
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.DH).setCipherAlgorithm(Algorithms.DESEDE).setKeySize(2048);
        KeyAgreementCryptography keyAgreementCryptography = new KeyAgreementCryptography(configuration);
        // 获取甲方密钥对
        Map<String,Key> keyMap = keyAgreementCryptography.initKey();
        String privateKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPrivateKey(keyMap));
        String publicKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPublicKey(keyMap));
        System.out.println("甲方DH私钥：" + privateKey);
        System.out.println("甲方DH公钥：" + publicKey);

        // 获取乙方密钥对
        Map<String,Key> keyMap1 = keyAgreementCryptography.initKey(keyAgreementCryptography.decodeKey(publicKey));
        System.out.println("加密前数据：" + data);
        String privateKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPrivateKey(keyMap1));
        String publicKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPublicKey(keyMap1));
        System.out.println("乙方DH私钥：" + privateKey1);
        System.out.println("乙方DH公钥：" + publicKey1);

        // 获取甲方本地对称密钥
        String secretKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.initSecretKey(keyAgreementCryptography.decodeKey(publicKey1), keyAgreementCryptography.decodeKey(privateKey)));
        System.out.println("甲方本地对称密钥：" + secretKey);

        // 获取乙方本地对称密钥
        String secretKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.initSecretKey(keyAgreementCryptography.decodeKey(publicKey), keyAgreementCryptography.decodeKey(privateKey1)));
        System.out.println("乙方本地对称密钥：" + secretKey1);

        // 甲方加密乙方解密
        String encryptData = keyAgreementCryptography.encrypt(data, keyAgreementCryptography.decodeKey(secretKey));
        System.out.println("甲方加密后数据：" + encryptData);
        String decryptData = keyAgreementCryptography.decrypt(encryptData, keyAgreementCryptography.decodeKey(secretKey1));
        System.out.println("乙方解密后数据：" + decryptData);
        // 乙方加密甲方解密
        String encryptData1 = keyAgreementCryptography.encrypt(data, keyAgreementCryptography.decodeKey(secretKey1));
        System.out.println("乙方加密后数据：" + encryptData1);
        String decryptData1 = keyAgreementCryptography.decrypt(encryptData1, keyAgreementCryptography.decodeKey(secretKey));
        System.out.println("甲方解密后数据：" + decryptData1);
    }

    /**
     * 测试使用ECDH_DES密钥协商算法进行加密解密
     * keySize DES_keySize
     * 160	80
     * 192	96
     * 224	112
     * 256	128
     */
    @Test
    public void testECDH_DESCryptoByBouncyCastle() {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.ECDH).setCipherAlgorithm(Algorithms.DES).setKeySize(256);
        KeyAgreementCryptography keyAgreementCryptography = new KeyAgreementCryptography(configuration);
        // 获取甲方密钥对
        Map<String,Key> keyMap = keyAgreementCryptography.initKey();
        String privateKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPrivateKey(keyMap));
        String publicKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPublicKey(keyMap));
        System.out.println("甲方ECDH私钥：" + privateKey);
        System.out.println("甲方ECDH公钥：" + publicKey);

        // 获取乙方密钥对
        Map<String,Key> keyMap1 = keyAgreementCryptography.initKey(keyAgreementCryptography.decodeKey(publicKey));
        System.out.println("加密前数据：" + data);
        String privateKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPrivateKey(keyMap1));
        String publicKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPublicKey(keyMap1));
        System.out.println("乙方ECDH私钥：" + privateKey1);
        System.out.println("乙方ECDH公钥：" + publicKey1);

        // 获取甲方本地对称密钥
        String secretKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.initSecretKey(keyAgreementCryptography.decodeKey(publicKey1), keyAgreementCryptography.decodeKey(privateKey)));
        System.out.println("甲方本地对称密钥：" + secretKey);

        // 获取乙方本地对称密钥
        String secretKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.initSecretKey(keyAgreementCryptography.decodeKey(publicKey), keyAgreementCryptography.decodeKey(privateKey1)));
        System.out.println("乙方本地对称密钥：" + secretKey1);

        // 甲方加密乙方解密
        String encryptData = keyAgreementCryptography.encrypt(data, keyAgreementCryptography.decodeKey(secretKey));
        System.out.println("甲方加密后数据：" + encryptData);
        String decryptData = keyAgreementCryptography.decrypt(encryptData, keyAgreementCryptography.decodeKey(secretKey1));
        System.out.println("乙方解密后数据：" + decryptData);
        // 乙方加密甲方解密
        String encryptData1 = keyAgreementCryptography.encrypt(data, keyAgreementCryptography.decodeKey(secretKey1));
        System.out.println("乙方加密后数据：" + encryptData1);
        String decryptData1 = keyAgreementCryptography.decrypt(encryptData1, keyAgreementCryptography.decodeKey(secretKey));
        System.out.println("甲方解密后数据：" + decryptData1);
    }

}

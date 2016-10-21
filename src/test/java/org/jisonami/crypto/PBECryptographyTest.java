package org.jisonami.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Security;

/**
 * Created by jisonami on 2016/10/21.
 */
public class PBECryptographyTest {

    private static final String data = "明文数据test中文";

    @Test
    public void testPBEWithMD5AndDES() {
        PBECryptography pbeCryptography = new PBECryptography();
        String password = "password";
        System.out.println("口令：" + password);
        String salt = pbeCryptography.encodeSalt(pbeCryptography.initSalt());
        System.out.println("盐：" + salt);
        String encryptData = pbeCryptography.encrypt(data, password, salt);
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = pbeCryptography.decrypt(encryptData, password, salt);
        System.out.println("解密后数据：" + decryptData);
    }

    @Test
    public void testPBEWithMD5AndTripleDES() {
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.PBE_WITH_MD5_AND_TripleDES).setCipherAlgorithm(Algorithms.PBE_WITH_MD5_AND_TripleDES).setPbeIterationCount(100);
        PBECryptography pbeCryptography = new PBECryptography(configuration);
        String password = "password";
        System.out.println("口令：" + password);
        String salt = pbeCryptography.encodeSalt(pbeCryptography.initSalt());
        System.out.println("盐：" + salt);
        String encryptData = pbeCryptography.encrypt(data, password, salt);
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = pbeCryptography.decrypt(encryptData, password, salt);
        System.out.println("解密后数据：" + decryptData);
    }

    @Test
    public void testPBEWithSHA1AndDESede() {
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.PBE_WITH_SHA1_AND_DESede).setCipherAlgorithm(Algorithms.PBE_WITH_SHA1_AND_DESede).setPbeIterationCount(100);
        PBECryptography pbeCryptography = new PBECryptography(configuration);
        String password = "password";
        System.out.println("口令：" + password);
        String salt = pbeCryptography.encodeSalt(pbeCryptography.initSalt());
        System.out.println("盐：" + salt);
        String encryptData = pbeCryptography.encrypt(data, password, salt);
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = pbeCryptography.decrypt(encryptData, password, salt);
        System.out.println("解密后数据：" + decryptData);
    }

    @Test
    public void testPBEWithSHA1AndRC2_40() {
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.PBE_WITH_SHA1_AND_RC2_40).setCipherAlgorithm(Algorithms.PBE_WITH_SHA1_AND_RC2_40).setPbeIterationCount(100);
        PBECryptography pbeCryptography = new PBECryptography(configuration);
        String password = "password";
        System.out.println("口令：" + password);
        String salt = pbeCryptography.encodeSalt(pbeCryptography.initSalt());
        System.out.println("盐：" + salt);
        String encryptData = pbeCryptography.encrypt(data, password, salt);
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = pbeCryptography.decrypt(encryptData, password, salt);
        System.out.println("解密后数据：" + decryptData);
    }

    @Test
    public void testPBEWithSHAAndIDEA_CBCByBouncyCastle() {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.PBE_WITH_SHA_AND_IDEA_CBC).setCipherAlgorithm(Algorithms.PBE_WITH_SHA_AND_IDEA_CBC).setPbeIterationCount(100);
        PBECryptography pbeCryptography = new PBECryptography(configuration);
        String password = "password";
        System.out.println("口令：" + password);
        String salt = pbeCryptography.encodeSalt(pbeCryptography.initSalt());
        System.out.println("盐：" + salt);
        String encryptData = pbeCryptography.encrypt(data, password, salt);
        System.out.println("加密前数据：" + data);
        System.out.println("加密后数据：" + encryptData);
        String decryptData = pbeCryptography.decrypt(encryptData, password, salt);
        System.out.println("解密后数据：" + decryptData);
    }

}

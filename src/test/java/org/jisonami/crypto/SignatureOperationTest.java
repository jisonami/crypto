package org.jisonami.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Key;
import java.security.Security;
import java.util.Map;

/**
 * Created by jisonami on 16-10-15.
 */
public class SignatureOperationTest {

    private static final String data = "明文数据test中文";

    @Test
    public void testMD5_WIEH_RSA(){
        NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography();
        Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
        String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
        String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
        System.out.println("RSA私钥：" + privateKey);
        System.out.println("RSA公钥：" + publicKey);
        SignatureOperation signatureOperation = new SignatureOperation();
        String sign = signatureOperation.sign(data, nonSymmetricCryptography.toPrivateKey(nonSymmetricCryptography.decodeKey(privateKey)));
        System.out.println("签名值：" + sign);
        System.out.println("验证签名：" + signatureOperation.verify(data, nonSymmetricCryptography.toPublicKey(nonSymmetricCryptography.decodeKey(publicKey)), sign));
    }

    @Test
    public void testSHA1_WIEH_RSA(){
        NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography();
        Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
        String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
        String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
        System.out.println("RSA私钥：" + privateKey);
        System.out.println("RSA公钥：" + publicKey);
        Configuration configuration = new Configuration();
        configuration.setSignatureAlgorithm(Algorithms.SHA1_WIEH_RSA);
        SignatureOperation signatureOperation = new SignatureOperation(configuration);
        String sign = signatureOperation.sign(data, nonSymmetricCryptography.toPrivateKey(nonSymmetricCryptography.decodeKey(privateKey)));
        System.out.println("签名值：" + sign);
        System.out.println("验证签名：" + signatureOperation.verify(data, nonSymmetricCryptography.toPublicKey(nonSymmetricCryptography.decodeKey(publicKey)), sign));
    }

    @Test
    public void testNONE_WIEH_RSA(){
        NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography();
        Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
        String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
        String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
        System.out.println("RSA私钥：" + privateKey);
        System.out.println("RSA公钥：" + publicKey);
        Configuration configuration = new Configuration();
        configuration.setSignatureAlgorithm(Algorithms.NONE_WIEH_RSA);
        SignatureOperation signatureOperation = new SignatureOperation(configuration);
        String sign = signatureOperation.sign(data, nonSymmetricCryptography.toPrivateKey(nonSymmetricCryptography.decodeKey(privateKey)));
        System.out.println("签名值：" + sign);
        System.out.println("验证签名：" + signatureOperation.verify(data, nonSymmetricCryptography.toPublicKey(nonSymmetricCryptography.decodeKey(publicKey)), sign));
    }

    @Test
    public void testSHA1_WIEH_DSA(){
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.DSA).setKeySize(1024);
        NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography(configuration);
        Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
        String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
        String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
        System.out.println("DSA私钥：" + privateKey);
        System.out.println("DSA公钥：" + publicKey);
        configuration.setSignatureAlgorithm(Algorithms.SHA1_WIEH_DSA);
        SignatureOperation signatureOperation = new SignatureOperation(configuration);
        String sign = signatureOperation.sign(data, nonSymmetricCryptography.toPrivateKey(nonSymmetricCryptography.decodeKey(privateKey)));
        System.out.println("签名值：" + sign);
        System.out.println("验证签名：" + signatureOperation.verify(data, nonSymmetricCryptography.toPublicKey(nonSymmetricCryptography.decodeKey(publicKey)), sign));
    }

    @Test
    public void testSHA256_WIEH_DSA(){
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.DSA).setKeySize(1024);
        NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography(configuration);
        Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
        String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
        String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
        System.out.println("DSA私钥：" + privateKey);
        System.out.println("DSA公钥：" + publicKey);
        configuration.setSignatureAlgorithm(Algorithms.SHA256_WIEH_DSA);
        SignatureOperation signatureOperation = new SignatureOperation(configuration);
        String sign = signatureOperation.sign(data, nonSymmetricCryptography.toPrivateKey(nonSymmetricCryptography.decodeKey(privateKey)));
        System.out.println("签名值：" + sign);
        System.out.println("验证签名：" + signatureOperation.verify(data, nonSymmetricCryptography.toPublicKey(nonSymmetricCryptography.decodeKey(publicKey)), sign));
    }

    @Test
    public void testSHA1_WIEH_ECDSAByBouncyCastle(){
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.ECDSA).setKeySize(256).setProvider(bouncyCastleProvider);
        NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography(configuration);
        Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
        String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
        String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
        System.out.println("ECDSA私钥：" + privateKey);
        System.out.println("ECDSA公钥：" + publicKey);
        configuration.setSignatureAlgorithm(Algorithms.SHA1_WIEH_ECDSA);
        SignatureOperation signatureOperation = new SignatureOperation(configuration);
        String sign = signatureOperation.sign(data, nonSymmetricCryptography.toPrivateKey(nonSymmetricCryptography.decodeKey(privateKey)));
        System.out.println("签名值：" + sign);
        System.out.println("验证签名：" + signatureOperation.verify(data, nonSymmetricCryptography.toPublicKey(nonSymmetricCryptography.decodeKey(publicKey)), sign));
    }

    @Test
    public void testSHA256_WIEH_ECDSAByBouncyCastle(){
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.ECDSA).setKeySize(256).setProvider(bouncyCastleProvider);
        NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography(configuration);
        Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
        String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
        String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
        System.out.println("ECDSA私钥：" + privateKey);
        System.out.println("ECDSA公钥：" + publicKey);
        configuration.setSignatureAlgorithm(Algorithms.SHA256_WIEH_ECDSA);
        SignatureOperation signatureOperation = new SignatureOperation(configuration);
        String sign = signatureOperation.sign(data, nonSymmetricCryptography.toPrivateKey(nonSymmetricCryptography.decodeKey(privateKey)));
        System.out.println("签名值：" + sign);
        System.out.println("验证签名：" + signatureOperation.verify(data, nonSymmetricCryptography.toPublicKey(nonSymmetricCryptography.decodeKey(publicKey)), sign));
    }


    @Test
    public void testSHA1_WIEH_DSAByBouncyCastle(){
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        Configuration configuration = new Configuration();
        configuration.setKeyAlgorithm(Algorithms.DSA).setKeySize(1024).setProvider(bouncyCastleProvider);
        NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography(configuration);
        Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
        String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
        String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
        System.out.println("DSA私钥：" + privateKey);
        System.out.println("DSA公钥：" + publicKey);
        configuration.setSignatureAlgorithm(Algorithms.SHA1_WIEH_DSA);
        SignatureOperation signatureOperation = new SignatureOperation(configuration);
        String sign = signatureOperation.sign(data, nonSymmetricCryptography.toPrivateKey(nonSymmetricCryptography.decodeKey(privateKey)));
        System.out.println("签名值：" + sign);
        System.out.println("验证签名：" + signatureOperation.verify(data, nonSymmetricCryptography.toPublicKey(nonSymmetricCryptography.decodeKey(publicKey)), sign));
    }

}

package org.jisonami.crypto;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by jisonami on 16-10-15.</p>
 * <p>处理密钥协商算法，如DH</p>
 * <p>使用Bouncy Castle组件包可支持ECDH</p>
 * <p>默认使用DH算法和UTF-8编码</p>
 *
 * @author jisonami
 * @see AbstractCryptography
 * @since 0.0.1
 */
public class KeyAgreementCryptography extends AbstractCryptography {

    public KeyAgreementCryptography() {
        getConfiguration().setKeyAlgorithm(Algorithms.DH).setCipherAlgorithm(Algorithms.DES).setKeySize(1024);
    }

    public KeyAgreementCryptography(Configuration configuration) {
        super(configuration);
    }

    /**
     * 加密操作
     * @param data 需要加密的数据
     * @param key 密钥的二进制形式
     * @return 加密后的数据
     */
    public String encrypt(String data, byte[] key) {
        byte[] result = null;
        try {
            result = this.encrypt(data.getBytes(getConfiguration().getCharset()), key);
            return new String(Base64.encodeBase64(result), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 加密操作
     * @param data 需要加密的数据
     * @param key 密钥的二进制形式
     * @return 加密后的数据 Base64URL形式
     */
    public String encryptURL(String data, byte[] key) {
        byte[] result = null;
        try {
            result = this.encrypt(data.getBytes(getConfiguration().getCharset()), key);
            return new String(Base64.encodeBase64URLSafe(result), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 加密操作
     * @param data 需要加密的数据
     * @param key 密钥的二进制形式
     * @return 加密后的数据
     */
    public byte[] encrypt(byte[] data, byte[] key) {
        Key k = toSecretKey(key);
        return this.encrypt(data, k);
    }


    /**
     * 解密操作
     * @param data 需要解密的数据
     * @param key 密钥的二进制形式
     * @return 解密后的数据
     */
    public String decrypt(String data, byte[] key) {
        byte[] result = Base64.decodeBase64(data);
        try {
            return new String(this.decrypt(result, key), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 解密操作
     * @param data 需要解密的数据 Base64URL形式
     * @param key 密钥的二进制形式
     * @return 解密后的数据
     */
    public String decryptURL(String data, byte[] key) {
        byte[] result = null;
        try {
            result = Base64.decodeBase64(data.getBytes(getConfiguration().getCharset()));
            return new String(this.decrypt(result, key), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 解密操作
     * @param data 需要解密的数据
     * @param key 密钥的二进制形式
     * @return 解密后的数据
     */
    public byte[] decrypt(byte[] data, byte[] key) {
        Key k = toSecretKey(key);
        return this.decrypt(data, k);
    }

    /**
     * 将公钥二进制形式转换成公钥对象
     * @param key 公钥的二进制形式
     * @return 公钥对象
     */
    public PublicKey toPublicKey(byte[] key) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance(getConfiguration().getKeyAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm(), e);
        }
        try {
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + key.toString(), e);
        }
    }

    /**
     * 将私钥二进制形式转换成私钥对象
     * @param key 私钥的二进制形式
     * @return 私钥对象
     */
    public PrivateKey toPrivateKey(byte[] key){
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance(getConfiguration().getKeyAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm(), e);
        }
        try {
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + key.toString(), e);
        }
    }

    /**
     * 将对称密钥二进制形式转换成对称密钥
     * @param key 对称密钥的二进制形式
     * @return 对称密钥对象
     */
    public SecretKey toSecretKey(byte[] key){
        return new SecretKeySpec(key, getConfiguration().getCipherAlgorithm());
    }

    /**
     * 根据甲方私钥和乙方公钥生成甲方本地对称密钥，或者根据乙方私钥和甲方公钥生成乙方本地对称密钥
     * @param publicKey 公钥二进制形式
     * @param privateKey 私钥二进制形式
     * @return 对称密钥对象
     */
    public byte[] initSecretKey(byte[] publicKey, byte[] privateKey) {
        PublicKey pubKey = this.toPublicKey(publicKey);
        PrivateKey priKey = this.toPrivateKey(privateKey);
        KeyAgreement keyAgreement = null;
        try {
            keyAgreement = KeyAgreement.getInstance(getConfiguration().getKeyAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm(), e);
        }
        try {
            keyAgreement.init(priKey);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + priKey.toString(), e);
        }
        try {
            keyAgreement.doPhase(pubKey, true);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + pubKey.toString(), e);
        }
        SecretKey secretKey = null;
        try {
            secretKey = keyAgreement.generateSecret(getConfiguration().getCipherAlgorithm());
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getCipherAlgorithm(), e);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + secretKey.toString(), e);
        }
    }

    /**
     * 取得公钥
     * @param keyMap 密钥对map
     * @return 公钥的二进制形式
     */
    public byte[] getPublicKey(Map<String, Key> keyMap){
        return keyMap.get(PUBLIC_KEY).getEncoded();
    }

    /**
     * 取得私钥
     * @param keyMap 密钥对map
     * @return 私钥的二进制形式
     */
    public byte[] getPrivateKey(Map<String, Key> keyMap){
        return keyMap.get(PRIVATE_KEY).getEncoded();
    }

    /**
     * 初始化密钥协商算法的甲方密钥对
     * @return 甲方密钥对
     */
    public Map<String, Key> initKey() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(getConfiguration().getKeyAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm(), e);
        }
        keyPairGenerator.initialize(getConfiguration().getKeySize());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        Map<String, Key> keyMap = new HashMap<String, Key>();
        keyMap.put(PRIVATE_KEY, privateKey);
        keyMap.put(PUBLIC_KEY, publicKey);
        return keyMap;
    }

    /**
     * 初始化密钥协商算法的乙方密钥对
     * @param publicKey 甲方公钥的二进制形式
     * @return 乙方密钥对
     */
    public Map<String, Key> initKey(byte[] publicKey) {
        PublicKey pubKey = this.toPublicKey(publicKey);
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(getConfiguration().getKeyAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm(), e);
        }
        AlgorithmParameterSpec algorithmParameterSpec = null;
        if(pubKey instanceof DHKey){
            algorithmParameterSpec = ((DHKey) pubKey).getParams();
        } else if(pubKey instanceof ECKey){
            algorithmParameterSpec = ((ECKey) pubKey).getParams();
        } else {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm());
        }
        try {
            keyPairGenerator.initialize(algorithmParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm(), e);
        }
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Map<String, Key> keyMap = new HashMap<String, Key>();
        keyMap.put(PRIVATE_KEY, keyPair.getPrivate());
        keyMap.put(PUBLIC_KEY, keyPair.getPublic());
        return keyMap;
    }

}

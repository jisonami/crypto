package org.jisonami.crypto;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.spec.AlgorithmParameterSpec;
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
public class KeyAgreementCryptography extends AbstractNonSymmetricCryptography {

    public KeyAgreementCryptography() {
        getConfiguration().setKeyAlgorithm(Algorithms.DH).setCipherAlgorithm(Algorithms.DES).setKeySize(Algorithms.KEYSIZE_1024);
    }

    public KeyAgreementCryptography(Configuration configuration) {
        super(configuration);
    }

    /**
     * 加密操作
     *
     * @param data 需要加密的数据
     * @param key  密钥的二进制形式
     * @return 加密后的数据
     */
    public String encrypt(String data, byte[] key) {
        try {
            byte[] result = this.encrypt(data.getBytes(getConfiguration().getCharset()), key);
            return new String(Base64.encodeBase64(result), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 加密操作
     *
     * @param data 需要加密的数据
     * @param key  密钥的二进制形式
     * @return 加密后的数据 Base64URL形式
     */
    public String encryptURL(String data, byte[] key) {
        try {
            byte[] result = this.encrypt(data.getBytes(getConfiguration().getCharset()), key);
            return new String(Base64.encodeBase64URLSafe(result), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 加密操作
     *
     * @param data 需要加密的数据
     * @param key  密钥的二进制形式
     * @return 加密后的数据
     */
    public byte[] encrypt(byte[] data, byte[] key) {
        Key k = toSecretKey(key);
        return this.encrypt(data, k);
    }


    /**
     * 解密操作
     *
     * @param data 需要解密的数据
     * @param key  密钥的二进制形式
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
     *
     * @param data 需要解密的数据 Base64URL形式
     * @param key  密钥的二进制形式
     * @return 解密后的数据
     */
    public String decryptURL(String data, byte[] key) {
        try {
            byte[] result = Base64.decodeBase64(data.getBytes(getConfiguration().getCharset()));
            return new String(this.decrypt(result, key), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 解密操作
     *
     * @param data 需要解密的数据
     * @param key  密钥的二进制形式
     * @return 解密后的数据
     */
    public byte[] decrypt(byte[] data, byte[] key) {
        Key k = toSecretKey(key);
        return this.decrypt(data, k);
    }

    /**
     * 将对称密钥二进制形式转换成对称密钥
     *
     * @param key 对称密钥的二进制形式
     * @return 对称密钥对象
     */
    public SecretKey toSecretKey(byte[] key) {
        return new SecretKeySpec(key, getConfiguration().getCipherAlgorithm());
    }

    /**
     * 根据甲方私钥和乙方公钥生成甲方本地对称密钥，或者根据乙方私钥和甲方公钥生成乙方本地对称密钥
     *
     * @param publicKey  公钥二进制形式
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
        try {
            SecretKey secretKey = keyAgreement.generateSecret(getConfiguration().getCipherAlgorithm());
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getCipherAlgorithm(), e);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO, e);
        }
    }

    /**
     * 初始化密钥协商算法的甲方密钥对
     *
     * @return 甲方密钥对
     */
    @Override
    public Map<String, Key> initKey() {
        return super.initKey();
    }

    /**
     * 初始化密钥协商算法的乙方密钥对
     *
     * @param publicKey 甲方公钥的二进制形式
     * @return 乙方密钥对
     */
    public Map<String, Key> initKey(byte[] publicKey) {
        PublicKey pubKey = this.toPublicKey(publicKey);
        KeyPairGenerator keyPairGenerator = getKeyPairGenerator();
        AlgorithmParameterSpec algorithmParameterSpec = null;
        if (pubKey instanceof DHKey) {
            algorithmParameterSpec = ((DHKey) pubKey).getParams();
        } else if (pubKey instanceof ECKey) {
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

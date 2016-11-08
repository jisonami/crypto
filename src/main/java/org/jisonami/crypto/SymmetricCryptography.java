package org.jisonami.crypto;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * <p>Created by jisonami on 2016/10/14.</p>
 * <p>处理对称加密算法相关操作，包括密钥生成，密钥还原，加解密相关操作</p>
 * <p>默认使用AES算法和UTF-8编码</p>
 * <p>可选算法包括DES、DESede、AES、RC2、RC4、Blowfish等</p>
 * <p>使用Bouncy Castle组件包还可支持IDEA算法</p>
 *
 * @author jisonami
 * @see AbstractCryptography
 * @since 0.0.1
 */
public class SymmetricCryptography extends AbstractCryptography {

    public SymmetricCryptography() {
        getConfiguration().setKeyAlgorithm(Algorithms.AES).setCipherAlgorithm(Algorithms.AES_ECB_PKCS5PADDING).setKeySize(Algorithms.KEYSIZE_128);
    }

    public SymmetricCryptography(Configuration configuration) {
        super(configuration);
    }

    /**
     * 获取对称密钥生成器
     *
     * @return 对称密钥生成器对象
     */
    private KeyGenerator getKeyGenerator() {
        KeyGenerator keyGenerator = null;
        try {
            if (getConfiguration().getProviderName() != null && !"".equals(getConfiguration().getProviderName())) {
                keyGenerator = KeyGenerator.getInstance(getConfiguration().getKeyAlgorithm(), getConfiguration().getProviderName());
            } else if (getConfiguration().getProvider() != null) {
                keyGenerator = KeyGenerator.getInstance(getConfiguration().getKeyAlgorithm(), getConfiguration().getProvider());
            } else {
                keyGenerator = KeyGenerator.getInstance(getConfiguration().getKeyAlgorithm());
            }
            return keyGenerator;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm(), e);
        } catch (NoSuchProviderException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_PROVIDER_EXCEPTION_INFO + getConfiguration().getProviderName(), e);
        }
    }

    /**
     * 生成一个密钥
     *
     * @return 密钥的二进制形式
     */
    public byte[] initKey() {
        KeyGenerator kg = getKeyGenerator();
        kg.init(getConfiguration().getKeySize());
        SecretKey secretKey = kg.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 转换密钥
     *
     * @param key 密钥的二进制形式
     * @return Key 密钥对象
     */
    public Key toSecretKey(byte[] key) {
        return new SecretKeySpec(key, getConfiguration().getKeyAlgorithm());
    }

    /**
     * 加密操作
     *
     * @param data 需要加密的数据
     * @param key  密钥的二进制形式
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
     *
     * @param data 需要加密的数据
     * @param key  密钥的二进制形式
     * @return 加密后的数据
     */
    public String encrypt(String data, String key) {
        return this.encrypt(data, this.decodeKey(key));
    }

    /**
     * 加密操作
     *
     * @param data 需要加密的数据
     * @param key  密钥的二进制形式
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
     *
     * @param data 需要加密的数据
     * @param key  密钥的二进制形式
     * @return 加密后的数据 Base64URL形式
     */
    public String encryptURL(String data, String key) {
        return this.encryptURL(data, this.decodeKey(key));
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
     * @param data 需要解密的数据
     * @param key  密钥的二进制形式
     * @return 解密后的数据
     */
    public String decrypt(String data, String key) {
        return this.decrypt(data, this.decodeKey(key));
    }

    /**
     * 解密操作
     *
     * @param data 需要解密的数据 Base64URL形式
     * @param key  密钥的二进制形式
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
     *
     * @param data 需要解密的数据 Base64URL形式
     * @param key  密钥的二进制形式
     * @return 解密后的数据
     */
    public String decryptURL(String data, String key) {
        return this.decrypt(data, this.decodeKey(key));
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

}

package org.jisonami.crypto;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * <p>Created by jisonami on 2016/10/21.</p>
 * <p>实现基于口令的机密算法</p>
 *
 * @author jisonami
 * @see AbstractCryptography
 * @since 0.0.1
 */
public class PBECryptography extends AbstractCryptography {

    public PBECryptography() {
        getConfiguration().setKeyAlgorithm(Algorithms.PBE_WITH_MD5_AND_DES).
                setCipherAlgorithm(Algorithms.PBE_WITH_MD5_AND_DES).
                setPbeIterationCount(Algorithms.PBE_ITERATION_COUNT_100);
    }

    public PBECryptography(Configuration configuration) {
        super(configuration);
    }

    /**
     * 获取对称密钥工厂，用于还原密钥对象
     *
     * @return 对称密钥工厂对象
     */
    protected SecretKeyFactory getSecretKeyFactory() {
        SecretKeyFactory keyFactory = null;
        try {
            if (getConfiguration().getProviderName() != null && !"".equals(getConfiguration().getProviderName())) {
                keyFactory = SecretKeyFactory.getInstance(getConfiguration().getKeyAlgorithm(), getConfiguration().getProviderName());
            } else if (getConfiguration().getProvider() != null) {
                keyFactory = SecretKeyFactory.getInstance(getConfiguration().getKeyAlgorithm(), getConfiguration().getProvider());
            } else {
                keyFactory = SecretKeyFactory.getInstance(getConfiguration().getKeyAlgorithm());
            }
            return keyFactory;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm(), e);
        } catch (NoSuchProviderException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_PROVIDER_EXCEPTION_INFO + getConfiguration().getProviderName(), e);
        }
    }

    /**
     * 根据口令获取密钥对象
     *
     * @param password 口令
     * @return 密钥对象
     */
    private Key toKey(String password) {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory secretKeyFactory = getSecretKeyFactory();
        try {
            return secretKeyFactory.generateSecret(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEYSPEC_EXCEPTION_INFO, e);
        }
    }

    /**
     * 初始化盐
     *
     * @return 盐的二进制形式
     */
    public byte[] initSalt() {
        return new SecureRandom().generateSeed(Algorithms.SALT_8);
    }

    /**
     * 加密操作
     *
     * @param data     需要加密的数据
     * @param password 口令
     * @param salt     盐
     * @return 加密后的数据
     */
    public byte[] encrypt(byte[] data, String password, byte[] salt) {
        Key key = this.toKey(password);
        AlgorithmParameterSpec algorithmParameterSpec = new PBEParameterSpec(salt, getConfiguration().getPbeIterationCount());
        return super.encrypt(data, key, algorithmParameterSpec);
    }

    /**
     * 加密操作
     *
     * @param data     需要加密的数据
     * @param password 口令
     * @param salt     盐
     * @return 加密后的数据
     */
    public String encrypt(String data, String password, String salt) {
        try {
            byte[] encryptData = this.encrypt(data.getBytes(getConfiguration().getCharset()), password, this.decodeSalt(salt));
            return new String(Base64.encodeBase64(encryptData), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 解密操作
     *
     * @param data     需要解密的数据
     * @param password 口令
     * @param salt     盐
     * @return 解密后的数据
     */
    public byte[] decrypt(byte[] data, String password, byte[] salt) {
        Key key = this.toKey(password);
        AlgorithmParameterSpec algorithmParameterSpec = new PBEParameterSpec(salt, getConfiguration().getPbeIterationCount());
        return super.decrypt(data, key, algorithmParameterSpec);
    }

    /**
     * 解密操作
     *
     * @param data     需要解密的数据
     * @param password 口令
     * @param salt     盐
     * @return 解密后的数据
     */
    public String decrypt(String data, String password, String salt) {
        try {
            byte[] decryptData = this.decrypt(Base64.decodeBase64(data), password, this.decodeSalt(salt));
            return new String(decryptData, getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 将二进制盐转换成字符串形式
     *
     * @param salt 盐的二进制形式
     * @return 盐的字符串形式
     */
    public String encodeSalt(byte[] salt) {
        return Base64.encodeBase64String(salt);
    }

    /**
     * 将字符串盐转换成二进制形式
     *
     * @param salt 盐的字符串形式
     * @return 盐的二进制形式
     */
    public byte[] decodeSalt(String salt) {
        return Base64.decodeBase64(salt);
    }
}

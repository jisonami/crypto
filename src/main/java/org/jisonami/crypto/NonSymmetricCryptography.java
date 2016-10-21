package org.jisonami.crypto;

import org.apache.commons.codec.binary.Base64;

import java.io.UnsupportedEncodingException;
import java.security.Key;

/**
 * <p>Created by jisonami on 2016/10/14.</p>
 * <p>处理非对称加密相关操作，包括密钥对（公钥私钥）生成，密钥对还原，加解密相关操作</p>
 * <p>默认使用RSA算法和UTF-8编码</p>
 * <p>另外，Java默认实现的非对称加密算法只有RSA，</p>
 * <p>使用Bouncy Castle扩展其他非对称加密算法也可使用以下代码，比如ELGAMAL算法</p>
 *
 * @author jisonami
 * @see AbstractCryptography
 * @since 0.0.1
 */
public class NonSymmetricCryptography extends AbstractNonSymmetricCryptography{

    public NonSymmetricCryptography() {
        getConfiguration().setKeyAlgorithm(Algorithms.RSA).setCipherAlgorithm(Algorithms.RSA_ECB_PKCS1PADDING).setKeySize(1024);
    }

    public NonSymmetricCryptography(Configuration configuration){
        super(configuration);
    }

    /**
     * 使用公钥加密操作
     * @param data 需要加密的数据
     * @param key 公钥的二进制形式
     * @return 加密后的数据
     */
    public String encryptByPublicKey(String data, byte[] key) {
        byte[] result = null;
        try {
            result = this.encryptByPublicKey(data.getBytes(getConfiguration().getCharset()), key);
            return new String(Base64.encodeBase64(result), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 使用公钥加密操作
     * @param data 需要加密的数据
     * @param key 密钥的二进制形式
     * @return 加密后的数据 Base64URL形式
     */
    public String encryptURLByPublicKey(String data, byte[] key) {
        byte[] result = null;
        try {
            result = this.encryptByPublicKey(data.getBytes(getConfiguration().getCharset()), key);
            return new String(Base64.encodeBase64URLSafe(result), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 使用公钥加密操作
     * @param data 需要加密的数据
     * @param key 公钥的二进制形式
     * @return 加密后的数据
     */
    public byte[] encryptByPublicKey(byte[] data, byte[] key) {
        Key k = toPublicKey(key);
        return this.encrypt(data, k);
    }


    /**
     * 使用公钥解密操作
     * @param data 需要解密的数据
     * @param key 公钥的二进制形式
     * @return 解密后的数据
     */
    public String decryptByPublicKey(String data, byte[] key) {
        byte[] result = Base64.decodeBase64(data);
        try {
            return new String(this.decryptByPublicKey(result, key), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 使用公钥解密操作
     * @param data 需要解密的数据 Base64URL形式
     * @param key 公钥钥的二进制形式
     * @return 解密后的数据
     */
    public String decryptURLByPublicKey(String data, byte[] key) {
        byte[] result = null;
        try {
            result = Base64.decodeBase64(data.getBytes(getConfiguration().getCharset()));
            return new String(this.decryptByPublicKey(result, key), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 使用公钥解密操作
     * @param data 需要解密的数据
     * @param key 公钥的二进制形式
     * @return 解密后的数据
     */
    public byte[] decryptByPublicKey(byte[] data, byte[] key) {
        Key k = toPublicKey(key);
        return this.decrypt(data, k);
    }

    /**
     * 使用私钥加密操作
     * @param data 需要加密的数据
     * @param key 私钥的二进制形式
     * @return 加密后的数据
     */
    public String encryptByPrivateKey(String data, byte[] key) {
        byte[] result = null;
        try {
            result = this.encryptByPrivateKey(data.getBytes(getConfiguration().getCharset()), key);
            return new String(Base64.encodeBase64(result), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 使用私钥加密操作
     * @param data 需要加密的数据
     * @param key 私钥的二进制形式
     * @return 加密后的数据 Base64URL形式
     */
    public String encryptURLByPrivateKey(String data, byte[] key) {
        byte[] result = null;
        try {
            result = this.encryptByPrivateKey(data.getBytes(getConfiguration().getCharset()), key);
            return new String(Base64.encodeBase64URLSafe(result), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 使用私钥加密操作
     * @param data 需要加密的数据
     * @param key 私钥的二进制形式
     * @return 加密后的数据
     */
    public byte[] encryptByPrivateKey(byte[] data, byte[] key) {
        Key k = toPrivateKey(key);
        return this.encrypt(data, k);
    }


    /**
     * 使用私钥解密操作
     * @param data 需要解密的数据
     * @param key 私钥的二进制形式
     * @return 解密后的数据
     */
    public String decryptByPrivateKey(String data, byte[] key) {
        byte[] result = Base64.decodeBase64(data);
        try {
            return new String(this.decryptByPrivateKey(result, key), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 使用私钥解密操作
     * @param data 需要解密的数据 Base64URL形式
     * @param key 私钥的二进制形式
     * @return 解密后的数据
     */
    public String decryptURLByPrivateKey(String data, byte[] key) {
        byte[] result = null;
        try {
            result = Base64.decodeBase64(data.getBytes(getConfiguration().getCharset()));
            return new String(this.decryptByPrivateKey(result, key), getConfiguration().getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + getConfiguration().getCharset(), e);
        }
    }

    /**
     * 使用私钥解密操作
     * @param data 需要解密的数据
     * @param key 私钥的二进制形式
     * @return 解密后的数据
     */
    public byte[] decryptByPrivateKey(byte[] data, byte[] key) {
        Key k = toPrivateKey(key);
        return this.decrypt(data, k);
    }

}

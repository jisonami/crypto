package org.jisonami.crypto;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * <p>加密解密抽象类，封装实际的加解密操作.</p>
 *
 * @author jisonami
 * @see SymmetricCryptography
 * @see NonSymmetricCryptography
 * @see KeyAgreementCryptography
 * @since 0.0.1
 */
public abstract class AbstractCryptography {

    /**
     * 表示公钥的字符串常量.
     * @see AbstractNonSymmetricCryptography#initKey()
     * @see AbstractNonSymmetricCryptography#getPublicKey(java.util.Map)
     */
    static final String PUBLIC_KEY = "PublicKey";

    /**
     * 表示私钥的字符串常量.
     * @see AbstractNonSymmetricCryptography#initKey()
     * @see AbstractNonSymmetricCryptography#getPrivateKey(java.util.Map)
     */
    static final String PRIVATE_KEY = "PrivateKey";

    /**
     * 加解密配置信息字段.
     */
    private Configuration configuration = new Configuration();

    /**
     * 用于继承的无参构造方法.
     */
    protected AbstractCryptography() {
    }

    /**
     * 用于继承的构造方法.
     *
     * @param configuration 加解密的配置信息
     */
    protected AbstractCryptography(final Configuration configuration) {
        this.configuration = configuration;
    }

    /**
     * 获取密码类.
     *
     * @return 密码对象
     */
    private Cipher getCipher() {
        Cipher cipher;
        try {
            if (configuration.getProviderName() != null && !"".equals(configuration.getProviderName())) {
                cipher = Cipher.getInstance(configuration.getCipherAlgorithm(), configuration.getProviderName());
            } else if (configuration.getProvider() != null) {
                cipher = Cipher.getInstance(configuration.getCipherAlgorithm(), configuration.getProvider());
            } else {
                cipher = Cipher.getInstance(configuration.getCipherAlgorithm());
            }
            return cipher;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + configuration.getKeyAlgorithm(), e);
        } catch (NoSuchPaddingException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_PADDING_EXCEPTION_INFO + configuration.getCipherAlgorithm(), e);
        } catch (NoSuchProviderException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_PROVIDER_EXCEPTION_INFO + configuration.getProviderName(), e);
        }
    }

    /**
     * 加密操作.
     *
     * @param data 需要加密的数据
     * @param key  密钥对象
     * @return 加密后的数据
     */
    protected byte[] encrypt(final byte[] data, final Key key) {
        Cipher cipher = getCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + key.toString(), e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new CryptographyException(ExceptionInfo.ILLEGAL_BLOCK_SIZE_EXCEPTION_INFO, e);
        } catch (BadPaddingException e) {
            throw new CryptographyException(ExceptionInfo.BAD_PADDING_EXCEPTION_INFO, e);
        }
    }

    /**
     * 加密操作.
     *
     * @param data                   需要加密的数据
     * @param key                    密钥对象
     * @param algorithmParameterSpec 算法参数规范材料
     * @return 加密后的数据
     */
    protected byte[] encrypt(final byte[] data, final Key key, final AlgorithmParameterSpec algorithmParameterSpec) {
        Cipher cipher = getCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, algorithmParameterSpec);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + key.toString(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_ALGORITHM_PARAMETER_EXCEPTION_INFO + algorithmParameterSpec.toString(), e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new CryptographyException(ExceptionInfo.ILLEGAL_BLOCK_SIZE_EXCEPTION_INFO, e);
        } catch (BadPaddingException e) {
            throw new CryptographyException(ExceptionInfo.BAD_PADDING_EXCEPTION_INFO, e);
        }
    }

    /**
     * 加密操作.
     *
     * @param data         需要加密的数据
     * @param key          密钥对象
     * @param secureRandom 安全随机数
     * @return 加密后的数据
     */
    protected byte[] encrypt(byte[] data, Key key, SecureRandom secureRandom) {
        Cipher cipher = getCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, secureRandom);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + key.toString(), e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new CryptographyException(ExceptionInfo.ILLEGAL_BLOCK_SIZE_EXCEPTION_INFO, e);
        } catch (BadPaddingException e) {
            throw new CryptographyException(ExceptionInfo.BAD_PADDING_EXCEPTION_INFO, e);
        }
    }

    /**
     * 加密操作.
     *
     * @param data                   需要加密的数据
     * @param key                    密钥对象
     * @param algorithmParameterSpec 算法参数规范材料
     * @param secureRandom           安全随机数
     * @return 加密后的数据
     */
    protected byte[] encrypt(byte[] data, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) {
        Cipher cipher = getCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, algorithmParameterSpec, secureRandom);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + key.toString(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_ALGORITHM_PARAMETER_EXCEPTION_INFO + algorithmParameterSpec.toString(), e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new CryptographyException(ExceptionInfo.ILLEGAL_BLOCK_SIZE_EXCEPTION_INFO, e);
        } catch (BadPaddingException e) {
            throw new CryptographyException(ExceptionInfo.BAD_PADDING_EXCEPTION_INFO, e);
        }
    }

    /**
     * 解密操作.
     *
     * @param data 需要解密的数据
     * @param key  密钥对象
     * @return 解密后的数据
     */
    protected byte[] decrypt(byte[] data, Key key) {
        Cipher cipher = getCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + key.toString(), e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new CryptographyException(ExceptionInfo.ILLEGAL_BLOCK_SIZE_EXCEPTION_INFO, e);
        } catch (BadPaddingException e) {
            throw new CryptographyException(ExceptionInfo.BAD_PADDING_EXCEPTION_INFO, e);
        }
    }

    /**
     * 解密操作.
     *
     * @param data                   需要解密的数据
     * @param key                    密钥对象
     * @param algorithmParameterSpec 算法参数规范材料
     * @return 解密后的数据
     */
    protected byte[] decrypt(final byte[] data, final Key key, final AlgorithmParameterSpec algorithmParameterSpec) {
        Cipher cipher = getCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, algorithmParameterSpec);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + key.toString(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_ALGORITHM_PARAMETER_EXCEPTION_INFO + algorithmParameterSpec.toString(), e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new CryptographyException(ExceptionInfo.ILLEGAL_BLOCK_SIZE_EXCEPTION_INFO, e);
        } catch (BadPaddingException e) {
            throw new CryptographyException(ExceptionInfo.BAD_PADDING_EXCEPTION_INFO, e);
        }
    }

    /**
     * 解密操作.
     *
     * @param data         需要解密的数据
     * @param key          密钥对象
     * @param secureRandom 安全随机数
     * @return 解密后的数据
     */
    protected byte[] decrypt(final byte[] data, final Key key, final SecureRandom secureRandom) {
        Cipher cipher = getCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, secureRandom);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + key.toString(), e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new CryptographyException(ExceptionInfo.ILLEGAL_BLOCK_SIZE_EXCEPTION_INFO, e);
        } catch (BadPaddingException e) {
            throw new CryptographyException(ExceptionInfo.BAD_PADDING_EXCEPTION_INFO, e);
        }
    }

    /**
     * 解密操作.
     *
     * @param data                   需要解密的数据
     * @param key                    密钥对象
     * @param algorithmParameterSpec 算法参数规范材料
     * @param secureRandom           安全随机数
     * @return 解密后的数据
     */
    protected byte[] decrypt(final byte[] data, final Key key, final AlgorithmParameterSpec algorithmParameterSpec, final SecureRandom secureRandom) {
        Cipher cipher = getCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, algorithmParameterSpec, secureRandom);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + key.toString(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_ALGORITHM_PARAMETER_EXCEPTION_INFO + algorithmParameterSpec.toString(), e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new CryptographyException(ExceptionInfo.ILLEGAL_BLOCK_SIZE_EXCEPTION_INFO, e);
        } catch (BadPaddingException e) {
            throw new CryptographyException(ExceptionInfo.BAD_PADDING_EXCEPTION_INFO, e);
        }
    }

    /**
     * 将二进制key编码成字符串形式.
     *
     * @param key 密钥的二进制形式
     * @return 密钥的字符串形式
     */
    public String encodeKey(final byte[] key) {
        return keyToBase64(key);
    }

    /**
     * 将字符串key解码成二进制形式.
     *
     * @param key 密钥的字符串形式
     * @return 密钥的二进制形式
     */
    public byte[] decodeKey(final String key) {
        return base64ToKey(key);
    }

    /**
     * 将密钥的二进制形式转换成Base64编码形式.
     *
     * @param key 密钥的二进制形式
     * @return 密钥的Base64字符串形式
     */
    private String keyToBase64(final byte[] key) {
        return Base64.encodeBase64String(key);
    }

    /**
     * 将密钥的Base64编码形式转换成二进制形式.
     *
     * @param key 密钥的Base64字符串形式
     * @return 密钥的二进制形式
     */
    private byte[] base64ToKey(final String key) {
        return Base64.decodeBase64(key);
    }

    /**
     * getter method.
     * @return configuration
     */
    public Configuration getConfiguration() {
        return configuration;
    }

}

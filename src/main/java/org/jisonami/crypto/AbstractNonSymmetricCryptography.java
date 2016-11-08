package org.jisonami.crypto;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by jisonami on 2016/10/21.</p>
 * <p>非对称密码抽象类，包含密钥对生成，公钥和私钥还原等操作</p>
 * <p>用于支持非对称密钥算法和密钥协商算法的非对称密钥处理部分</p>
 *
 * @author jisonami
 * @see AbstractCryptography
 * @see NonSymmetricCryptography
 * @see KeyAgreementCryptography
 * @since 0.0.1
 */
public abstract class AbstractNonSymmetricCryptography extends AbstractCryptography {

    /**
     * 用于继承无参构造方法.
     */
    protected AbstractNonSymmetricCryptography() {
    }

    /**
     * 用于继承的构造方法.
     * @param configuration 加解密的配置信息
     */
    protected AbstractNonSymmetricCryptography(Configuration configuration) {
        super(configuration);
    }

    /**
     * 获取非对称密钥工厂，用于还原密钥对象.
     *
     * @return 非对称密钥工厂对象
     */
    protected KeyFactory getKeyFactory() {
        KeyFactory keyFactory = null;
        try {
            if (getConfiguration().getProviderName() != null && !"".equals(getConfiguration().getProviderName())) {
                keyFactory = KeyFactory.getInstance(getConfiguration().getKeyAlgorithm(), getConfiguration().getProviderName());
            } else if (getConfiguration().getProvider() != null) {
                keyFactory = KeyFactory.getInstance(getConfiguration().getKeyAlgorithm(), getConfiguration().getProvider());
            } else {
                keyFactory = KeyFactory.getInstance(getConfiguration().getKeyAlgorithm());
            }
            return keyFactory;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm(), e);
        } catch (NoSuchProviderException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_PROVIDER_EXCEPTION_INFO + getConfiguration().getProviderName(), e);
        }
    }

    /**
     * 获取非对称密钥生成器.
     *
     * @return 非对称密钥生成器对象
     */
    protected KeyPairGenerator getKeyPairGenerator() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            if (getConfiguration().getProviderName() != null && !"".equals(getConfiguration().getProviderName())) {
                keyPairGenerator = KeyPairGenerator.getInstance(getConfiguration().getKeyAlgorithm(), getConfiguration().getProviderName());
            } else if (getConfiguration().getProvider() != null) {
                keyPairGenerator = KeyPairGenerator.getInstance(getConfiguration().getKeyAlgorithm(), getConfiguration().getProvider());
            } else {
                keyPairGenerator = KeyPairGenerator.getInstance(getConfiguration().getKeyAlgorithm());
            }
            return keyPairGenerator;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + getConfiguration().getKeyAlgorithm(), e);
        } catch (NoSuchProviderException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_PROVIDER_EXCEPTION_INFO + getConfiguration().getProviderName(), e);
        }
    }

    /**
     * 生成秘钥对.
     *
     * @return 密钥对
     */
    public Map<String, Key> initKey() {
        KeyPairGenerator keyPairGenerator = getKeyPairGenerator();
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
     * 将公钥二进制形式转换成公钥对象.
     *
     * @param key 公钥的二进制形式
     * @return 公钥对象
     */
    public PublicKey toPublicKey(byte[] key) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = getKeyFactory();
        try {
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEYSPEC_EXCEPTION_INFO, e);
        }
    }

    /**
     * 将私钥二进制形式转换成私钥对象.
     *
     * @param key 私钥的二进制形式
     * @return 私钥对象
     */
    public PrivateKey toPrivateKey(byte[] key) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = getKeyFactory();
        try {
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEYSPEC_EXCEPTION_INFO, e);
        }
    }

    /**
     * 取得公钥.
     *
     * @param keyMap 密钥对map
     * @return 公钥的二进制形式
     */
    public byte[] getPublicKey(Map<String, Key> keyMap) {
        return keyMap.get(PUBLIC_KEY).getEncoded();
    }

    /**
     * 取得私钥.
     *
     * @param keyMap 密钥对map
     * @return 私钥的二进制形式
     */
    public byte[] getPrivateKey(Map<String, Key> keyMap) {
        return keyMap.get(PRIVATE_KEY).getEncoded();
    }
}

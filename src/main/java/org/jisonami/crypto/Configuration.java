package org.jisonami.crypto;

import java.security.Provider;

/**
 * <p>配置类，对于密钥生成以及加密解密相关参数的配置.</p>
 *
 * @author jisonami
 * @see AbstractCryptography
 * @see SymmetricCryptography
 * @see NonSymmetricCryptography
 * @see KeyAgreementCryptography
 * @since 0.0.1
 */
public class Configuration {

    /**
     * 字符编码，默认utf-8.
     */
    private String charset = "utf-8";

    /**
     * 密钥长度.
     */
    private int keySize;

    /**
     * 密钥算法.
     */
    private String keyAlgorithm;

    /**
     * 加解密算法.
     */
    private String cipherAlgorithm;

    /**
     * 密钥生成以及加解密提供者.
     */
    private Provider provider;

    /**
     * 密钥生成以及加解密提供者的名字缩写，比如BouncyCastleProvider的缩写为“BC”,优先级高于provider属性.
     */
    private String providerName;

    /**
     * 签名算法.
     */
    private String signatureAlgorithm;

    /**
     * PBE算法消息摘要迭代次数.
     */
    private int pbeIterationCount;

    /**
     * a getter method.
     * @return a String of charset
     */
    public String getCharset() {
        return charset;
    }

    /**
     * a setter method.
     * @param charset a String of charset
     * @return Configuration
     */
    public Configuration setCharset(String charset) {
        this.charset = charset;
        return this;
    }

    /**
     * a getter method.
     * @return keySize
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * a setter method.
     * @param keySize keySize
     * @return Configuration
     */
    public Configuration setKeySize(int keySize) {
        this.keySize = keySize;
        return this;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public Configuration setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        return this;
    }

    public String getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    public Configuration setCipherAlgorithm(String cipherAlgorithm) {
        this.cipherAlgorithm = cipherAlgorithm;
        return this;
    }

    public Provider getProvider() {
        return provider;
    }

    public Configuration setProvider(Provider provider) {
        this.provider = provider;
        return this;
    }

    public String getProviderName() {
        return providerName;
    }

    public Configuration setProviderName(String providerName) {
        this.providerName = providerName;
        return this;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public int getPbeIterationCount() {
        return pbeIterationCount;
    }

    public void setPbeIterationCount(int pbeIterationCount) {
        this.pbeIterationCount = pbeIterationCount;
    }

    @Override
    public String toString() {
        return "Configuration{" +
                "charset='" + charset + '\'' +
                ", keySize=" + keySize +
                ", keyAlgorithm='" + keyAlgorithm + '\'' +
                ", cipherAlgorithm='" + cipherAlgorithm + '\'' +
                ", provider=" + provider +
                ", providerName='" + providerName + '\'' +
                '}';
    }
}

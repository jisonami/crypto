package org.jisonami.crypto;

import org.apache.commons.codec.binary.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * <p>Created by jisonami on 16-10-15.</p>
 * <p>封装签名相关操作</p>
 * <p>签名操作基于非对称密钥算法，私钥签名，公钥验证签名</p>
 *
 * @author jisonami
 * @see NonSymmetricCryptography
 * @since 0.0.1
 */
public class SignatureOperation {

    private Configuration configuration = new Configuration();

    public SignatureOperation() {
        configuration.setSignatureAlgorithm(Algorithms.SHA1_WIEH_RSA);
    }

    public SignatureOperation(Configuration configuration) {
        this.configuration = configuration;
    }

    /**
     * 签名操作
     *
     * @param data       需要签名的数据
     * @param privateKey 私钥对象
     * @return 签名
     */
    public byte[] sign(byte[] data, PrivateKey privateKey) {
        Signature signature = null;
        try {
            signature = Signature.getInstance(configuration.getSignatureAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + configuration.getSignatureAlgorithm(), e);
        }
        try {
            signature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + privateKey.toString(), e);
        }
        try {
            signature.update(data);
            return signature.sign();
        } catch (SignatureException e) {
            throw new CryptographyException(ExceptionInfo.SIGNATURE_EXCEPTION_INFO + configuration.getSignatureAlgorithm(), e);
        }
    }

    /**
     * 签名操作
     *
     * @param data       需要签名的数据
     * @param privateKey 私钥对象
     * @return 签名
     */
    public String sign(String data, PrivateKey privateKey) {
        try {
            return new String(Base64.encodeBase64(this.sign(data.getBytes(configuration.getCharset()), privateKey)), configuration.getCharset());
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + configuration.getCharset(), e);
        }
    }

    /**
     * 验证签名操作
     *
     * @param data      需要验证签名的数据
     * @param publicKey 公钥对象
     * @param sign      签名
     * @return 签名验证结果，验证成功返回true，验证失败返回false
     */
    public boolean verify(byte[] data, PublicKey publicKey, byte[] sign) {
        Signature signature = null;
        try {
            signature = Signature.getInstance(configuration.getSignatureAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(ExceptionInfo.NO_SUCH_ALGORITHM_EXCEPTION_INFO + configuration.getSignatureAlgorithm(), e);
        }
        try {
            signature.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(ExceptionInfo.INVALID_KEY_EXCEPTION_INFO + publicKey.toString(), e);
        }
        try {
            signature.update(data);
            return signature.verify(sign);
        } catch (SignatureException e) {
            throw new CryptographyException(ExceptionInfo.SIGNATURE_EXCEPTION_INFO + configuration.getSignatureAlgorithm(), e);
        }
    }

    /**
     * 验证签名操作
     *
     * @param data      需要验证签名的数据
     * @param publicKey 公钥对象
     * @param sign      签名
     * @return 签名验证结果，验证成功返回true，验证失败返回false
     */
    public boolean verify(String data, PublicKey publicKey, String sign) {
        try {
            return this.verify(data.getBytes(configuration.getCharset()), publicKey, Base64.decodeBase64(sign.getBytes(configuration.getCharset())));
        } catch (UnsupportedEncodingException e) {
            throw new CryptographyException(ExceptionInfo.UNSUPPORTED_ENCODING_EXCEPTION_INFO + configuration.getCharset(), e);
        }
    }
}

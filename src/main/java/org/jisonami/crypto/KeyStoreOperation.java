package org.jisonami.crypto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * <p>Created by jisonami on 16-10-15.</p>
 * <p>封装密钥库相关操作</p>
 *
 * @author jisonami
 * @since 0.0.1
 */
public class KeyStoreOperation {

    public static final String CERT_TYPE = "x.509";

    /**
     * 在密钥库中获取私钥对象
     * @param keyStorePath 密钥库地址
     * @param alias 私钥别名
     * @param password 密钥库密码
     * @return 私钥对象
     */
    public PrivateKey getPrivateKeyByKeyStore(String keyStorePath, String alias, String password){
        KeyStore keyStore = getKeyStore(keyStorePath, password);
        try {
            Key key = keyStore.getKey(alias, password.toCharArray());
            if(key instanceof PrivateKey){
                return (PrivateKey) key;
            } else {
                throw new CryptographyException("别名为" + alias + "的密钥不是私钥");
            }
        } catch (KeyStoreException e) {
            throw new CryptographyException(keyStorePath + "密钥库解析失败！" + e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException("不支持该密钥库的算法" + e);
        } catch (UnrecoverableKeyException e) {
            throw new CryptographyException("无法处理别名为" + alias + "的密钥" + e);
        }
    }

    /**
     * 在证书中获取公钥对象
     * @param certificate 证书对象
     * @return 公钥对象
     */
    public PublicKey getPublicKeyByCertficate(Certificate certificate){
        return certificate.getPublicKey();
    }

    /**
     * 在证书中获取公钥对象
     * @param certficatePath 证书路径
     * @return 公钥对象
     */
    public PublicKey getPublicKeyByCertficate(String certficatePath){
        Certificate certificate = this.getCertificate(certficatePath);
        return certificate.getPublicKey();
    }

    /**
     * 通过证书路径获取证书对象
     * @param certficatePath 证书路径
     * @return 证书对象
     */
    public Certificate getCertificate(String certficatePath){
        CertificateFactory certificateFactory = null;
        try {
            certificateFactory = CertificateFactory.getInstance(CERT_TYPE);
        } catch (CertificateException e) {
            throw new CryptographyException("不支持的证书规范" + CERT_TYPE + e);
        }
        FileInputStream fileInputStream = null;
        try {
            fileInputStream = new FileInputStream(certficatePath);
        } catch (FileNotFoundException e) {
            throw new CryptographyException(certficatePath + "文件不存在！" + e);
        }
        Certificate certificate = null;
        try {
            certificate = certificateFactory.generateCertificate(fileInputStream);
        } catch (CertificateException e) {
            throw new CryptographyException(certficatePath + "证书解析失败！" + e);
        }
        try {
            fileInputStream.close();
        } catch (IOException e) {
            throw new CryptographyException(certficatePath + "文件关闭失败！" + e);
        }
        return certificate;
    }

    /**
     * 在密钥库中获取证书
     * @param keyStorePath 密钥库路径
     * @param alias 证书别名
     * @param password 密钥库密码
     * @return 证书对象
     */
    public Certificate getCertficate(String keyStorePath, String alias, String password){
        KeyStore keyStore = this.getKeyStore(keyStorePath, password);
        try {
            return keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new CryptographyException(keyStorePath + "密钥库解析失败！" + e);
        }
    }

    /**
     * 通过密钥库路径获取密钥库对象
     * @param keyStorePath 密钥库路径
     * @param password 密钥库密码
     * @return 密钥库对象
     */
    public KeyStore getKeyStore(String keyStorePath, String password) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new CryptographyException(keyStorePath + "密钥库解析失败！" + e);
        }
        FileInputStream fileInputStream = null;
        try {
            fileInputStream = new FileInputStream(keyStorePath);
        } catch (FileNotFoundException e) {
            throw new CryptographyException(keyStorePath + "文件不存在！" + e);
        }
        try {
            keyStore.load(fileInputStream, password.toCharArray());
        } catch (IOException e) {
            throw new CryptographyException(keyStorePath + "密钥库解析失败！" + e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(keyStorePath + "密钥库解析失败！" + e);
        } catch (CertificateException e) {
            throw new CryptographyException(keyStorePath + "密钥库解析失败！" + e);
        }
        try {
            fileInputStream.close();
        } catch (IOException e) {
            throw new CryptographyException(keyStorePath + "文件关闭失败！" + e);
        }
        return keyStore;
    }

}

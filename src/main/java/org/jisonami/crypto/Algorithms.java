package org.jisonami.crypto;

/**
 * <p>Created by jisonami on 16-10-14.</p>
 * <p>常用的密码算法参数常量</p>
 * <p>常量未列全</p>
 *
 * @author jisonami
 * @since 0.0.1
 */
public interface Algorithms {

    // 对称密钥算法相关
    String AES = "AES";
    String AES_ECB_PKCS5PADDING = "AES/ECB/PKCS5Padding";
    String DES = "DES";
    String DES_ECB_PKCS5PADDING = "DES/ECB/PKCS5Padding";
    String DESEDE = "DESede";
    String DESEDE_ECB_PKCS5PADDING = "DESede/ECB/PKCS5Padding";
    String RC2 = "RC2";
    String RC4 = "RC4";
    String BLOWFISH = "Blowfish";
    String BLOWFISH_ECB_PKCS5PADDING = "Blowfish/ECB/PKCS5Padding";
    String IDEA = "IDEA";

    // 基于口令的加解密算法PBE相关
    String PBE_WITH_MD5_AND_DES = "PBEWithMD5AndDES";   // DES密钥默认长度56
    String PBE_WITH_MD5_AND_TripleDES = "PBEWithMD5AndTripleDES";   // TripleDES密钥默认长度168
    String PBE_WITH_SHA1_AND_DESede = "PBEWithSHA1AndDESede";   // DESede密钥默认长度168
    String PBE_WITH_SHA1_AND_RC2_40 = "PBEWithSHA1AndRC2_40";   // RC2_40密钥默认长度128
    String PBE_WITH_SHA_AND_IDEA_CBC = "PBEWithSHAAndIDEA-CBC"; // IDEA密钥默认长度128

     // 密钥协商算法相关
    String DH = "DH";
    String ECDH = "ECDH";

    // 非对称密钥算法相关
    String RSA = "RSA";
    String RSA_ECB_PKCS1PADDING = "RSA/ECB/PKCS1Padding";
    String RSA_ECB_OAEPWITHMD5ANDMGF1PADDING = "RSA/ECB/OAEPWITHMD5AndMGF1Padding";
    String RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING = "RSA/ECB/OAEPWITHSHA1AndMGF1Padding";
    String RSA_ECB_OAEPWITHSHA256ANDMGF1PADDING = "RSA/ECB/OAEPWITHSHA256AndMGF1Padding";
    String RSA_ECB_OAEPWITHSHA384ANDMGF1PADDING = "RSA/ECB/OAEPWITHSHA384AndMGF1Padding";
    String RSA_ECB_OAEPWITHSHA512ANDMGF1PADDING = "RSA/ECB/OAEPWITHSHA512AndMGF1Padding";
    String DSA = "DSA";
    String ECDSA = "ECDSA";
    String ELGAMAL = "ELGAMAL";
    String ELGAMAL_ECB_PKCS1PADDING = "ELGAMAL/ECB/PKCS1Padding";
    
    // 签名算法相关
    String NONE_WIEH_RSA = "NONEwithRSA";
    String MD2_WIEH_RSA = "MD2withRSA";
    String MD5_WIEH_RSA = "MD5withRSA";
    String SHA1_WIEH_RSA = "SHA1withRSA";
    String SHA224_WIEH_RSA = "SHA224withRSA";
    String SHA256_WIEH_RSA = "SHA256withRSA";
    String SHA384_WIEH_RSA = "SHA384withRSA";
    String SHA512_WIEH_RSA = "SHA512withRSA";
    String SHA1_WIEH_DSA = "SHA1withDSA";
    String SHA224_WIEH_DSA = "SHA224withDSA";
    String SHA256_WIEH_DSA = "SHA256withDSA";
    String SHA384_WIEH_DSA = "SHA384withDSA";
    String SHA512_WIEH_DSA = "SHA512withDSA";
    String NONE_WIEH_ECDSA = "NONEwithECDSA";
    String SHA1_WIEH_ECDSA = "SHA1withECDSA";
    String SHA224_WIEH_ECDSA = "SHA224withECDSA";
    String SHA256_WIEH_ECDSA = "SHA256withECDSA";
    String SHA384_WIEH_ECDSA = "SHA384withECDSA";
    String SHA512_WIEH_ECDSA = "SHA512withECDSA";

}

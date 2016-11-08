package org.jisonami.crypto;

/**
 * <p>Created by jisonami on 2016/10/20.</p>
 * <p>抛出的异常信息</p>
 *
 * @author jisonami
 * @since 0.0.1
 */
public interface ExceptionInfo {
    
    String NO_SUCH_ALGORITHM_EXCEPTION_INFO = "NoSuchAlgorithmException--不支持的算法";

    String NO_SUCH_PADDING_EXCEPTION_INFO = "NoSuchPaddingException--不支持的填充方式";

    String INVALID_KEY_EXCEPTION_INFO = "InvalidKeyException--无效的密钥";

    String ILLEGAL_BLOCK_SIZE_EXCEPTION_INFO = "IllegalBlockSizeException--非法块大小异常";

    String BAD_PADDING_EXCEPTION_INFO = "BadPaddingException--错误的填充方式";

    String UNSUPPORTED_ENCODING_EXCEPTION_INFO = "UnsupportedEncodingException--不支持的编码格式";

    String SIGNATURE_EXCEPTION_INFO = "SignatureException--签名异常";

    String NO_SUCH_PROVIDER_EXCEPTION_INFO = "NoSuchProviderException--没有这样的安全提供者";

    String INVALID_KEYSPEC_EXCEPTION_INFO = "InvalidKeySpecException--无效的密钥规范异常";

    String INVALID_ALGORITHM_PARAMETER_EXCEPTION_INFO = "InvalidAlgorithmParameterException--无效的算法参数规范异常";
}

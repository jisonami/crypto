package org.jisonami.crypto;

/**
 * <p>Created by jisonami on 2016/10/14.</p>
 * <p>加解密相关操作异常，将密钥生成以及加解密过程中的异常包装成运行时异常</p>
 *
 * @author jisonami
 * @since 0.0.1
 */
public class CryptographyException extends RuntimeException {

    private static final long serialVersionUID = 1067809060581174305L;

    public CryptographyException() {
    }

    public CryptographyException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptographyException(String message) {
        super(message);
    }

    public CryptographyException(Throwable cause) {
        super(cause);
    }
}

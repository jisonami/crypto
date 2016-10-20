# crypto
对Java平台密钥生成、加解密等封装的类库

### 分析
直接使用Java提供的API需要处理如下类之间的关系

![Java API类图](http://jisonami.org/images/Java_Security/Crypto/JavaCryptoClassDiagram.png)

使用crypto类库则只需要处理如下类之间的关系

![crypto API类图](http://jisonami.org/images/Java_Security/Crypto/CryptoClassDiagram.png)

### SymmetricCryptography实现对称密钥算法加解密

#### 默认使用AES算法、128位密钥长度

```java
SymmetricCryptography symmetricCryptography = new SymmetricCryptography();
String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
System.out.println("AES密钥：" + key);
String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
System.out.println("加密前数据：" + data);
System.out.println("加密后数据：" + encryptData);
String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
System.out.println("解密后数据：" + decryptData);
```



### NonSymmetricCryptography实现非对称密钥算法加解密


### KeyAgreementCryptography实现密钥协商算法加解密

更详细的API请参考[crypto的JavaDoc文档](/doc)
# crypto
对Java平台密钥生成、加解密等封装的类库

### 分析
直接使用Java提供的API需要处理如下类之间的关系

![Java API类图](http://jisonami.org/images/Java_Security/Crypto/JavaCryptoClassDiagram.png)

使用crypto类库则只需要处理如下类之间的关系

![crypto API类图](http://jisonami.org/images/Java_Security/Crypto/CryptoClassDiagram.png)

### 需要注意的地方

#### Java安全API出口限制

密钥长度限制

比如默认情况下AES算法如果使用256位长度，会抛出以下异常

```java
java.security.InvalidKeyException: Illegal key size
```

解决办法：到oracle官网下载Java密码扩展无限制权限策略文件，然后将JAVA_HOME/jre/lib/security目录下的local_policy.jar和US_export_policy.jar替换即可

[JDK6的下载地址](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html) 

[JDK7的下载地址](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html) 

[JDK8的下载地址](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html) 

#### 使用BouncyCastle组件包扩展Java尚未支持的加解密算法

BouncyCastle官方地址:[http://www.bouncycastle.org/](http://www.bouncycastle.org/)

加解密前加入以下两行代码即可

```java
BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
Security.addProvider(bouncyCastleProvider);
```

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

#### 使用DES算法、56位密钥长度

```java
Configuration configuration = new Configuration();
configuration.setKeyAlgorithm(Algorithms.DES).setCipherAlgorithm(Algorithms.DES_ECB_PKCS5PADDING).setKeySize(56);
SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
System.out.println("DES密钥：" + key);
String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
System.out.println("加密前数据：" + data);
System.out.println("加密后数据：" + encryptData);
String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
System.out.println("解密后数据：" + decryptData);
```

#### 使用DESede算法、168位密钥长度

```java
Configuration configuration = new Configuration();
configuration.setKeyAlgorithm(Algorithms.DESEDE).setCipherAlgorithm(Algorithms.DESEDE_ECB_PKCS5PADDING).setKeySize(168);
SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
System.out.println("DESede密钥：" + key);
String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
System.out.println("加密前数据：" + data);
System.out.println("加密后数据：" + encryptData);
String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
System.out.println("解密后数据：" + decryptData);
```

#### 使用Blowfish算法、128位密钥长度

```java
Configuration configuration = new Configuration();
configuration.setKeyAlgorithm(Algorithms.BLOWFISH).setCipherAlgorithm(Algorithms.BLOWFISH_ECB_PKCS5PADDING).setKeySize(128);
SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
System.out.println("Blowfish密钥：" + key);
String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
System.out.println("加密前数据：" + data);
System.out.println("加密后数据：" + encryptData);
String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
System.out.println("解密后数据：" + decryptData);
```

#### 使用RC2算法、128位密钥长度

```java
Configuration configuration = new Configuration();
configuration.setKeyAlgorithm(Algorithms.RC2).setCipherAlgorithm(Algorithms.RC2).setKeySize(128);
SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
System.out.println("RC2密钥：" + key);
String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
System.out.println("加密前数据：" + data);
System.out.println("加密后数据：" + encryptData);
String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
System.out.println("解密后数据：" + decryptData);
```

#### 使用RC4算法、128位密钥长度

```java
Configuration configuration = new Configuration();
configuration.setKeyAlgorithm(Algorithms.RC4).setCipherAlgorithm(Algorithms.RC4).setKeySize(128);
SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
System.out.println("RC4密钥：" + key);
String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
System.out.println("加密前数据：" + data);
System.out.println("加密后数据：" + encryptData);
String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
System.out.println("解密后数据：" + decryptData);
```

#### 使用IDEA算法、128位密钥长度

需要使用BouncyCastleProvider扩展支持

```java
BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
Security.addProvider(bouncyCastleProvider);
Configuration configuration = new Configuration();
configuration.setKeyAlgorithm(Algorithms.IDEA).setCipherAlgorithm(Algorithms.IDEA).setKeySize(128);
SymmetricCryptography symmetricCryptography = new SymmetricCryptography(configuration);
String key = symmetricCryptography.encodeKey(symmetricCryptography.initKey());
System.out.println("IDEA密钥：" + key);
String encryptData = symmetricCryptography.encrypt(data, symmetricCryptography.decodeKey(key));
System.out.println("加密前数据：" + data);
System.out.println("加密后数据：" + encryptData);
String decryptData = symmetricCryptography.decrypt(encryptData, symmetricCryptography.decodeKey(key));
System.out.println("解密后数据：" + decryptData);
```

### NonSymmetricCryptography实现非对称密钥算法加解密

#### 默认使用RSA算法、1024位密钥长度

```java
NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography();
Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
System.out.println("RSA私钥：" + privateKey);
System.out.println("RSA公钥：" + publicKey);
System.out.println("加密前数据：" + data);
// 公钥加密私钥解密
String encryptData = nonSymmetricCryptography.encryptByPublicKey(data, nonSymmetricCryptography.decodeKey(publicKey));
System.out.println("公钥加密后数据：" + encryptData);
String decryptData = nonSymmetricCryptography.decryptByPrivateKey(encryptData, nonSymmetricCryptography.decodeKey(privateKey));
System.out.println("私钥解密后数据：" + decryptData);
// 私钥加密公钥解密
String encryptData1 = nonSymmetricCryptography.encryptByPrivateKey(data, nonSymmetricCryptography.decodeKey(privateKey));
System.out.println("公钥加密后数据：" + encryptData1);
String decryptData1 = nonSymmetricCryptography.decryptByPublicKey(encryptData1, nonSymmetricCryptography.decodeKey(publicKey));
System.out.println("私钥解密后数据：" + decryptData1);
```

#### 使用ELGAMAL算法、512位密钥长度

需要使用BouncyCastleProvider扩展支持

```java
BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
Security.addProvider(bouncyCastleProvider);
Configuration configuration = new Configuration();
configuration.setKeyAlgorithm(Algorithms.ELGAMAL).setCipherAlgorithm(Algorithms.ELGAMAL_ECB_PKCS1PADDING).setKeySize(512);
NonSymmetricCryptography nonSymmetricCryptography = new NonSymmetricCryptography(configuration);
Map<String,Key> keyMap = nonSymmetricCryptography.initKey();
String privateKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPrivateKey(keyMap));
String publicKey = nonSymmetricCryptography.encodeKey(nonSymmetricCryptography.getPublicKey(keyMap));
System.out.println("ELGAMAL私钥：" + privateKey);
System.out.println("ELGAMAL公钥：" + publicKey);
System.out.println("加密前数据：" + data);
// 公钥加密私钥解密
String encryptData = nonSymmetricCryptography.encryptByPublicKey(data, nonSymmetricCryptography.decodeKey(publicKey));
System.out.println("公钥加密后数据：" + encryptData);
String decryptData = nonSymmetricCryptography.decryptByPrivateKey(encryptData, nonSymmetricCryptography.decodeKey(privateKey));
System.out.println("私钥解密后数据：" + decryptData);
```

### KeyAgreementCryptography实现密钥协商算法加解密

#### 使用DH密钥交换算法、DES本地密钥算法、1024位密钥长度

```java
KeyAgreementCryptography keyAgreementCryptography = new KeyAgreementCryptography();
// 获取甲方密钥对
Map<String,Key> keyMap = keyAgreementCryptography.initKey();
String privateKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPrivateKey(keyMap));
String publicKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPublicKey(keyMap));
System.out.println("甲方DH私钥：" + privateKey);
System.out.println("甲方DH公钥：" + publicKey);

// 获取乙方密钥对
Map<String,Key> keyMap1 = keyAgreementCryptography.initKey(keyAgreementCryptography.decodeKey(publicKey));
System.out.println("加密前数据：" + data);
String privateKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPrivateKey(keyMap1));
String publicKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPublicKey(keyMap1));
System.out.println("乙方DH私钥：" + privateKey1);
System.out.println("乙方DH公钥：" + publicKey1);

// 获取甲方本地对称密钥
String secretKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.initSecretKey(keyAgreementCryptography.decodeKey(publicKey1), keyAgreementCryptography.decodeKey(privateKey)));
System.out.println("甲方本地对称密钥：" + secretKey);

// 获取乙方本地对称密钥
String secretKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.initSecretKey(keyAgreementCryptography.decodeKey(publicKey), keyAgreementCryptography.decodeKey(privateKey1)));
System.out.println("乙方本地对称密钥：" + secretKey1);

// 甲方加密乙方解密
String encryptData = keyAgreementCryptography.encrypt(data, keyAgreementCryptography.decodeKey(secretKey));
System.out.println("甲方加密后数据：" + encryptData);
String decryptData = keyAgreementCryptography.decrypt(encryptData, keyAgreementCryptography.decodeKey(secretKey1));
System.out.println("乙方解密后数据：" + decryptData);
// 乙方加密甲方解密
String encryptData1 = keyAgreementCryptography.encrypt(data, keyAgreementCryptography.decodeKey(secretKey1));
System.out.println("乙方加密后数据：" + encryptData1);
String decryptData1 = keyAgreementCryptography.decrypt(encryptData1, keyAgreementCryptography.decodeKey(secretKey));
System.out.println("甲方解密后数据：" + decryptData1);
```

#### 使用ECDH密钥交换算法、DES本地密钥算法、256位密钥长度

需要使用BouncyCastleProvider扩展支持

```java
BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
Security.addProvider(bouncyCastleProvider);
Configuration configuration = new Configuration();
configuration.setKeyAlgorithm(Algorithms.ECDH).setCipherAlgorithm(Algorithms.DES).setKeySize(256);
KeyAgreementCryptography keyAgreementCryptography = new KeyAgreementCryptography(configuration);
// 获取甲方密钥对
Map<String,Key> keyMap = keyAgreementCryptography.initKey();
String privateKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPrivateKey(keyMap));
String publicKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPublicKey(keyMap));
System.out.println("甲方ECDH私钥：" + privateKey);
System.out.println("甲方ECDH公钥：" + publicKey);

// 获取乙方密钥对
Map<String,Key> keyMap1 = keyAgreementCryptography.initKey(keyAgreementCryptography.decodeKey(publicKey));
System.out.println("加密前数据：" + data);
String privateKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPrivateKey(keyMap1));
String publicKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.getPublicKey(keyMap1));
System.out.println("乙方ECDH私钥：" + privateKey1);
System.out.println("乙方ECDH公钥：" + publicKey1);

// 获取甲方本地对称密钥
String secretKey = keyAgreementCryptography.encodeKey(keyAgreementCryptography.initSecretKey(keyAgreementCryptography.decodeKey(publicKey1), keyAgreementCryptography.decodeKey(privateKey)));
System.out.println("甲方本地对称密钥：" + secretKey);

// 获取乙方本地对称密钥
String secretKey1 = keyAgreementCryptography.encodeKey(keyAgreementCryptography.initSecretKey(keyAgreementCryptography.decodeKey(publicKey), keyAgreementCryptography.decodeKey(privateKey1)));
System.out.println("乙方本地对称密钥：" + secretKey1);

// 甲方加密乙方解密
String encryptData = keyAgreementCryptography.encrypt(data, keyAgreementCryptography.decodeKey(secretKey));
System.out.println("甲方加密后数据：" + encryptData);
String decryptData = keyAgreementCryptography.decrypt(encryptData, keyAgreementCryptography.decodeKey(secretKey1));
System.out.println("乙方解密后数据：" + decryptData);
// 乙方加密甲方解密
String encryptData1 = keyAgreementCryptography.encrypt(data, keyAgreementCryptography.decodeKey(secretKey1));
System.out.println("乙方加密后数据：" + encryptData1);
String decryptData1 = keyAgreementCryptography.decrypt(encryptData1, keyAgreementCryptography.decodeKey(secretKey));
System.out.println("甲方解密后数据：" + decryptData1);
```

更详细的API请参考[crypto的JavaDoc文档](http://jisonami.org/docs/Java_Security/Crypto/doc/)
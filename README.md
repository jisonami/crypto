# crypto
对Java平台密钥生成、加解密等封装的类库

### 分析
直接使用Java提供的API需要处理如下类之间的关系
<img src='http://g.gravizo.com/g?
@startuml;

interface Key;
interface PublicKey;
interface PrivateKey;
interface SecretKey;
abstract class KeyPairGenerator {;
generateKeyPair%28%29;
};
class KeyPair {;
getPrivate%28%29;
getPublic%28%29;
};
class KeyGenerator {;
generateKey%28%29;
};
class Cipher {;
init%28int CIPHER_MODE, Key key%29;
doFinal%28String data%29;
};

Cipher --> Key:%E5%AE%9E%E7%8E%B0%E5%8A%A0%E8%A7%A3%E5%AF%86;
Key <|-- PublicKey;
Key <|-- PrivateKey;
Key <|-- SecretKey;
KeyPairGenerator --> KeyPair:%E7%94%9F%E6%88%90%E9%9D%9E%E5%AF%B9%E7%A7%B0%E5%AF%86%E9%92%A5%E5%AF%B9;
KeyPair --> PrivateKey;
KeyPair --> PublicKey;
KeyGenerator --> SecretKey:%E7%94%9F%E6%88%90%E5%AF%B9%E7%A7%B0%E5%AF%86%E9%92%A5;

class SecretKeySpec;
class SecretKeyFactory {;
generateSecret%28KeySpec keySpec%29;
};
SecretKey <-- SecretKeySpec:%E8%BF%98%E5%8E%9F%E5%AF%B9%E7%A7%B0%E5%AF%86%E9%92%A5;
SecretKey <-- SecretKeyFactory:%E8%BF%98%E5%8E%9F%E5%AF%B9%E7%A7%B0%E5%AF%86%E9%92%A5;
class KeyFactory {;
generatePublic%28KeySpec keySpec%29;
generatePrivate%28KeySpec keySpec%29;
};
PrivateKey <-- KeyFactory:%E8%BF%98%E5%8E%9F%E5%85%AC%E9%92%A5;
PublicKey <-- KeyFactory:%E8%BF%98%E5%8E%9F%E5%85%AC%E9%92%A5;
@enduml
'/>
使用crypto类库则只需要处理如下类之间的关系
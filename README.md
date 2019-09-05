#@ctsy/crypto 加解密工具
```typescript
import { RSA, MD5 } from './index'
import { AES } from '../dist';
//RSA 加密
let data = "a", key = "a";
RSA.publicEncrypt(data, key)
RSA.privateEncrypt(data, key);
RSA.publicDecrypt(data, key);
RSA.privateDecrypt(data, key)


//AES 加减密
let aes = new AES('MuY78fCSsp', 'AES-128-ECB'.toLowerCase());
let s = aes.encode('a');
console.log(s)
console.log(aes.decode(s))

//MD5

MD5.encode(data);

MD5.password_hash(data, key);
MD5.password_verify(data, key);


```
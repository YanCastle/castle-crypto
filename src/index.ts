import * as crypto from 'crypto'
import { env } from 'process';
export class RSA {
    /**
     * 公钥加密
     * @param data 
     * @param key 
     */
    static publicEncrypt(data: string | Buffer, key: string) {
        var buffer = 'string' == typeof data ? Buffer.from(data, "base64") : data;
        var encrypted = crypto.publicEncrypt({
            key, padding: crypto.constants.RSA_PKCS1_PADDING
        }, buffer);
        return encrypted;
    }
    /**
     * 私钥加密
     * @param data 
     * @param key 
     */
    static privateEncrypt(data: string | Buffer, key: string) {
        var buffer = 'string' == typeof data ? Buffer.from(data, "base64") : data;
        var encrypted = crypto.privateEncrypt({
            key, padding: crypto.constants.RSA_PKCS1_PADDING
        }, buffer);
        return encrypted;
    }
    /**
     * 公钥解密
     * @param data 
     * @param key 
     */
    static publicDecrypt(data: string | Buffer, key: string) {
        var buffer = 'string' == typeof data ? Buffer.from(data, "base64") : data;
        var decrypted = crypto.publicDecrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, buffer);
        return decrypted;
    }
    /**
     * 私钥解密
     * @param data 数据内容
     * @param key 私钥
     */
    static privateDecrypt(data: string | Buffer, key: string) {
        var buffer = 'string' == typeof data ? Buffer.from(data, "base64") : data;
        var decrypted = crypto.privateDecrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, buffer);
        return decrypted;
    }
}

export class AES {
    key: string = "";
    encoder: crypto.Cipher;
    decoder: crypto.Decipher;
    constructor(key: string, type: string = "aes128") {
        this.key = key;
        this.encoder = crypto.createCipher(type, Buffer.from(this.key, 'base64'));
        this.decoder = crypto.createDecipher(type, Buffer.from(this.key, 'base64'))
    }
    encode(data: string) {
        this.encoder.update(data)
        return this.encoder.final('base64');
    }
    decode(data: string) {
        this.decoder.update(Buffer.from(data, 'base64'));
        return this.decoder.final('utf-8')
    }
}

/**
 * MD5加密
 */
export class MD5 {
    /**
     * 加密
     * @param data 
     */
    static encode(data: string | Uint8Array | Buffer | Uint8ClampedArray | Uint16Array | Uint32Array | Int8Array | Int16Array | Int32Array | Float32Array | Float64Array | DataView) {
        return crypto.createHash('md5').update(data).digest('hex')
    }
    /**
     * 用md5进行密码加密
     * @param data 
     * @param salt 
     */
    static password_hash(data: string, salt: string = ""): string {
        return MD5.encode([salt, data, salt].join(''))
    }
    /**
     * 用md5进行密码验证
     * @param password 
     * @param secret 
     * @param salt 
     */
    static password_verify(password: string, secret: string, salt: string = ""): boolean {
        return MD5.password_hash(password, salt) == secret;
    }
}
/**
 * 密码处理类
 */
export class Password {
    salt: string = env.PASSWORD_SALT || "abced"
    /**
     * 构造函数
     * @param salt 
     */
    constructor(salt: string) {
        this.salt = salt;
    }
    /**
     * 编码
     * @param password 
     */
    encode(password: string) {
        return MD5.password_hash(password, this.salt)
    }
    /**
     * 验证
     * @param password 
     * @param secret 
     */
    verify(password: string, secret: string) {
        return MD5.password_verify(password, secret, this.salt)
    }
}
/**
 * Base64编码方案
 */
export class Base64 {
    /**
     * 编码
     * @param data 
     */
    static encode(data: string | Buffer) {
        return data instanceof Buffer ? data.toString('base64') : Buffer.from(data).toString('base64');
    }
    /**
     * 解码
     * @param data 
     */
    static decode(data: string) {
        return Buffer.from(data, 'base64').toString()
    }
}
/**
 * sha密码加密
 */
export class PasswordSha1 {
    static hash(pwd: string, salt: string) {
        return crypto.createHmac('sha1', salt).update(pwd).digest().toString('base64');
    }
    static verify(key: string, pwd: string, salt: string) {
        return key == PasswordSha1.hash(pwd, salt);
    }
}
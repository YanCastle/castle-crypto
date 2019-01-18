import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import { env } from 'process';
export class RSA {
    /**
     * 公钥加密
     * @param data 
     * @param key 
     */
    static publicEncrypt(data: string, key: string) {
        var buffer = Buffer.from(data);
        var encrypted = crypto.publicEncrypt({
            key, padding: crypto.constants.RSA_PKCS1_PADDING
        }, buffer);
        return encrypted.toString("base64");
    }
    /**
     * 私钥加密
     * @param data 
     * @param key 
     */
    static privateEncrypt(data: string, key: string) {
        var buffer = Buffer.from(data);
        var encrypted = crypto.privateEncrypt({
            key, padding: crypto.constants.RSA_PKCS1_PADDING
        }, buffer);
        return encrypted.toString("base64");
    }
    /**
     * 公钥解密
     * @param data 
     * @param key 
     */
    static publicDecrypt(data: string, key: string) {
        var buffer = Buffer.from(data, "base64");
        var decrypted = crypto.publicDecrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, buffer);
        return decrypted.toString("utf8");
    }
    /**
     * 私钥解密
     * @param data 
     * @param key 
     */
    static privateDecrypt(data: string, key: string) {
        var buffer = Buffer.from(data, "base64");
        var decrypted = crypto.privateDecrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, buffer);
        return decrypted.toString("utf8");
    }
}
const md5 = crypto.createHash('md5');
/**
 * MD5加密
 */
export class MD5 {
    /**
     * 加密
     * @param data 
     */
    static encode(data: string) {
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
import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
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
export class MD5 {
    static encode(data: string) {
        return crypto.createHash('md5').update(data).digest('hex')
    }
}
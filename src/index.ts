import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
export class RSA {
    /**
     * 公钥加密
     * @param data 
     * @param keyfile 
     */
    static publicEncrypt(data: string, keyfile: string) {
        var absolutePath = path.resolve(keyfile);
        var key = fs.readFileSync(absolutePath, "utf8");
        var buffer = Buffer.from(data);
        var encrypted = crypto.publicEncrypt({
            key, padding: crypto.constants.RSA_PKCS1_PADDING
        }, buffer);
        return encrypted.toString("base64");
    }
    /**
     * 私钥加密
     * @param data 
     * @param keyfile 
     */
    static privateEncrypt(data: string, keyfile: string) {
        var absolutePath = path.resolve(keyfile);
        var key = fs.readFileSync(absolutePath, "utf8");
        var buffer = Buffer.from(data);
        var encrypted = crypto.privateEncrypt({
            key, padding: crypto.constants.RSA_PKCS1_PADDING
        }, buffer);
        return encrypted.toString("base64");
    }
    /**
     * 公钥解密
     * @param data 
     * @param keyfile 
     */
    static publicDecrypt(data: string, keyfile: string) {
        var absolutePath = path.resolve(keyfile);
        var key = fs.readFileSync(absolutePath, 'utf-8');
        var buffer = Buffer.from(data, "base64");
        var decrypted = crypto.publicDecrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, buffer);
        return decrypted.toString("utf8");
    }
    /**
     * 私钥解密
     * @param toDecrypt 
     * @param relativeOrAbsolutePathtoPrivateKey 
     */
    static privateDecrypt(toDecrypt, relativeOrAbsolutePathtoPrivateKey) {
        var absolutePath = path.resolve(relativeOrAbsolutePathtoPrivateKey);
        var key = fs.readFileSync(absolutePath, 'utf-8');
        var buffer = Buffer.from(toDecrypt, "base64");
        var decrypted = crypto.privateDecrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, buffer);
        return decrypted.toString("utf8");
    }
}
export class MD5 {
    static encode(data: string) {
        return crypto.createHash('md5').update(data).digest('hex')
    }
}
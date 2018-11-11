import Foundation
import CoreFoundation
import Security

class Crypt{
    func main() {
        let plainText = "abcde12345"
        
        // 公開鍵と秘密鍵を生成する
        let keyPair = generateKeyPair()
        let blockSize = SecKeyGetBlockSize(keyPair.publicKey!)
        
        // 暗号化する
        let encryptedData = crypt(
            plainText: plainText,
            publicKey: keyPair.publicKey, 
            blockSize: blockSize)
        
        // 復号化する
        let decryptedData = decrypt(
            publicKey: keyPair.publicKey!,
            privateKey: keyPair.privateKey!,
            encryptedData: encryptedData,
            blockSize: blockSize)
        
        // 復号したデータを文字列にする
        let decryptText = NSString(
            bytes: decryptedData,
            length: blockSize,
            encoding: String.Encoding.utf8.rawValue)!
        
        print(decryptText)
        
    }
    
    func generateKeyPair() -> (publicKey: SecKey?, privateKey: SecKey?) {
        // RSA暗号を使用する
        let parameters: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 1024
        ]
        
        // SecKeyGeneratePairを生成する
        var publicKey: SecKey?
        var privateKey: SecKey?
        let osStatus = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
        
        // 公開鍵と秘密鍵を返却する
        switch osStatus {
        case noErr:
            return (publicKey, privateKey)
        default:
            return (nil, nil)
        }
    }
    
    func crypt(plainText: String!, publicKey: SecKey!, blockSize:Int) -> [UInt8]{
        let plainTextData = [UInt8](plainText.utf8)
        let plainTextDataLength = plainText.count
        
        // 公開鍵のブロック長に応じた変数を用意する
        var encryptedData = [UInt8](
            repeating: 0,
            count: Int(blockSize)
        )
        var encryptedDataLength = blockSize
        
        // 暗号化対象の文字列を暗号化する
        SecKeyEncrypt(
            publicKey!,
            SecPadding.PKCS1,
            plainTextData,
            plainTextDataLength,
            &encryptedData,
            &encryptedDataLength
        )
        
        return encryptedData
    }
    
    func decrypt(publicKey: SecKey!, privateKey: SecKey!, encryptedData: [UInt8]!, blockSize:Int) -> [UInt8]{
        // 公開鍵のブロック長に応じた変数を用意する
        var decryptedData = [UInt8](
            repeating: 0,
            count: Int(blockSize)
        )
        
        var decryptedDataLength = blockSize
        
        // 暗号化されたデータを復号する
        SecKeyDecrypt(
            privateKey!,
            SecPadding.PKCS1,
            encryptedData,
            blockSize,
            &decryptedData,
            &decryptedDataLength
        )
        
        return decryptedData
    }
}

Crypt().main()

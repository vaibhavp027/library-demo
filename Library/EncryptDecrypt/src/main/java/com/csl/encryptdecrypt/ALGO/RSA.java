package com.csl.encryptdecrypt.ALGO;

import javax.crypto.Cipher;
import java.security.*;
import java.security.cert.CertPath;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private static final String PRIVATE_KEY_STRING = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+5Ou5twUrhcymDS8AQ5h6yQPMQFu9JaK/J15bZOyTulB8I3ELHbzDK2Z9UFeVkypEO/Om0CpnNWSj4QAl1aSvPcE4iDI7KT/d64XJuymPuAoURYQBJILC7CZmDdRcqV4SbglW4FbmxvgHpLCEtfaL+jTNev6UaPQv8fuMDoLyErOSIVH+6hpVGGVTsS5KmoNMQiicNyaE4E9gcZ+pyvrjT99QWh6eN1hqXda+wNPH8/zG1QSE+/kZOiQAZQzY4vXHGejGptknQpDIza/V3QVpdb0ZUBxfMZ8aWmIWYZb2YGFakBDS3VzP7HVHpIeUYse9RgDjYti0yuzm9fQ02FOFAgMBAAECggEACsb51/5ROGfRaf6MjMNENIpswHdRtpgNXCVo2lgUUzLNoHSPyUTgh1RH8QM8LqGkXT3VP7G48yK8j9QAIiKxrYMbCYoG6/gkNu85Gm6KpiaJyyMxlK7vAvo6IMDfIGwfd4Lm3BTGUzkgf634mUV8qeJyYLd08AQM5TgQL5QSKIB00hHVhhvOUYkYqskMSYSxaqQtmLicgFnEDuS7b/aFe96E97Csmrl5MDhqxIuy8pymRuMbeAnEbUYFdmdLYK6z+xdy4oIsk2Zx0OPssGD8tI9w6YthGgJBxjLWERPK6DM53Wu+Swbd0q/wnf5TUjgMj/4oDzIUSKo784OVK2OEcQKBgQDWsvHFWL7YFZJAeWXxb4FfjQpdMHoKipdC9tDFjD+hSSnkJJEaCXGplovEmm91Cd4QqFPSFecoTMJcHvXlcVlOcjC/ep6XhhhTdn6zQeBXiigIrB8e15Ng/tBH1ne2jDnyJLCFt8Sq4//kx1thHTeYiq+Ectd95mPudXtIwp59LwKBgQDjna/+H5K8e1gMyHZ51267Lc9w2/L+BXm6uUeTN7NhL5jG/OZVb4sEOmLieRyLas9JseuV2UU3Q9uAK9RS21rV+rpAr5dnKNf1aSivV4nAB/oFuY5Z3tdE/rbrNP3N31jwImOTfl81jN/hu9ySFhIVdNJDDrOFPKdvhA3bZXKViwKBgQDALt4McSwj8OtBm2mNfOqpxW6JjGMyHGzaHGU08B3lGcDN342jaOC9lWz3R+aNNY/6CTM+0yxf/pXcMDqcb6Ipfj30qKZdrEMKMv+nJkjTE3BSkwAoc4ARSwbVxzzRwyP7hKwehikdb4oYF/vMKoMhoMMMJGCQ6jJ5ud/peYy1MQKBgBT/kSLiisj0oBTd0YBADaka+s4wnGQu4SIGwcGlG9lVaMTCxAURu0Nyl3jJL4b1HZZw4Yj7eFU232MdqALU1bZz4QbirBcKP5IWV3iFnOGoWrp4edd0pWtqDDn6s4dwmWXd5k3PFL1995F9oUWg3543Hsas7obWJ6Q0DIs2+rEtAoGBAJb4jzm0LoBm0UlsT/er4w9N7tapJG3UGUY0QlE3jIrc+W5h6gk81bwMQ7TzTArHBO7r12iYApqgJ2LORBI3anwBqmkC0n3a1FMPV1PBwK7bhZxifg67JYvZt/YJVMMrLrrwUF4+ikJnw9UBLTTweUOKS89EjqWiT/3+9nB6rg7T";
    private static final String PUBLIC_KEY_STRING = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvuTrubcFK4XMpg0vAEOYeskDzEBbvSWivydeW2Tsk7pQfCNxCx28wytmfVBXlZMqRDvzptAqZzVko+EAJdWkrz3BOIgyOyk/3euFybspj7gKFEWEASSCwuwmZg3UXKleEm4JVuBW5sb4B6SwhLX2i/o0zXr+lGj0L/H7jA6C8hKzkiFR/uoaVRhlU7EuSpqDTEIonDcmhOBPYHGfqcr640/fUFoenjdYal3WvsDTx/P8xtUEhPv5GTokAGUM2OL1xxnoxqbZJ0KQyM2v1d0FaXW9GVAcXzGfGlpiFmGW9mBhWpAQ0t1cz+x1R6SHlGLHvUYA42LYtMrs5vX0NNhThQIDAQAB";
    public void init(){
        try {
//          Key Generation
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        }catch (Exception exception){
            System.out.println("1"+exception);
        }
    }

    public void initFromString(){
        try {
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(PUBLIC_KEY_STRING));
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpecPublic);
            privateKey = keyFactory.generatePrivate(keySpecPrivate);
        }catch (Exception exception){
            System.out.println("2" + exception);
        }

    }

//  Encryption method
    public String encryptText(String message) throws Exception{
        byte[] messageToByte = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(messageToByte);
        return encode(encryptedBytes);
    }

//    Decryption method
    public String decryptText(String encryptedMessage) throws Exception{
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    private String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public void printKeys(){
        System.out.println("Private Key: " + encode(privateKey.getEncoded()));
        System.out.println("Public Key: "  + encode(publicKey.getEncoded()));
    }
}

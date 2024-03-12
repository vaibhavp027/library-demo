package com.csl.encryptdecrypt;

import com.csl.encryptdecrypt.ALGO.AES;
import com.csl.encryptdecrypt.ALGO.RSA;

public class Main {
    public static void main(String[] args) {
//        Using AES
//        try{
//            AES aes = new AES();
//            aes.initFromString("LSxYeQ2W7WtF/VqXmc6sbw==", "+CVBDEJOroO4bLaX");
//            String encryptedMessage = aes.encryptText("Vaibhav");
//            System.out.println("En: " + encryptedMessage);
//            String decryptedMessage = aes.decryptText(encryptedMessage);
//            System.out.println("De: " + decryptedMessage);
//            aes.exportKeys();
//        }catch (Exception ex){
//            System.out.println(ex);
//        }

//        Using RSA
        try{
            RSA rsa = new RSA();
            rsa.initFromString();
            String encryptedMessage = rsa.encryptText("Vaibhav");
            String decryptedMessage = rsa.decryptText(encryptedMessage);
            System.out.println("En: " + encryptedMessage);
            System.out.println("De: " + decryptedMessage);
            //rsa.printKeys();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        System.out.println("Hello world!");
    }
}
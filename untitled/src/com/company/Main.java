package com.company;

import javax.crypto.Cipher;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Main {

    public static void main(String[] args) throws Exception {
        String encr = "a2FEC6fNuD5r1nh1qqha6NQfrvCHWO0pVgcMs5P64kACAYjS5HrYH+SHGmbA+dy4T8mbOcr/f0FNf4suAS9JcYVehEFWEIykvy6GauUqwC0iVFlLAj9WbACZA7CqXA3vnqWYd5rXs7ZIjj75JTvorpQto5cqXiDRnyzg42oHew5I6K7nsUASwo0Lw0HCB5yZ6MzTBbzflycE6/eURV1f5LZQ6SM3NrDnmIE1vO0UAE05p3bbAV40rdEdr6SrWnCU10s9+OV8FcKOLyvPS4yFquCmvTVvQMO/+ebwWGZFwBm4gOvVfH0v1detXfom5U9U48bcv1xUEWn61hJDn1gWWg==";//s_s_s
        String decr= decryptMessage(encr,getPublicKeyFromBytes("MFI_KEY.pub"));
        decr = decr+"_"+"jhxgfsjfdshjfddshjdfsszhfdhg";//decrypt_apikey
        String tokenId = encryptMessage(decr,getPrivateKeyFromBytes("MFI_KEY.pk"));
        System.out.println(decr);
        System.out.println(tokenId);
    }

    private static Map<String,Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate(); //  encrypt
        PublicKey publicKey = keyPair.getPublic(); // decrypt

        Map<String, Object> keys = new HashMap<>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }

    // Decrypt using RSA public key
    private static String decryptMessage(String encryptedText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }

    // Encrypt using RSA private key
    private static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    private static void savePrivateKey(PrivateKey privateKey,String fileName){
        try {
            FileOutputStream outputStream = new FileOutputStream(fileName+".pk");
            outputStream.write(privateKey.getEncoded());
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private static void savePublicKey(PublicKey publicKey,String fileName){
        try {
            FileOutputStream outputStream = new FileOutputStream(fileName+".pub");
            outputStream.write(publicKey.getEncoded());
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static PrivateKey getPrivateKeyFromBytes(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(getBytesFromFile(fileName));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pvt = kf.generatePrivate(ks);

        return pvt;
    }
    private static PublicKey getPublicKeyFromBytes(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        X509EncodedKeySpec ks = new X509EncodedKeySpec(getBytesFromFile(fileName));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(ks);

        return pub;
    }

    private static byte[] getBytesFromFile(String fileName) throws IOException {
        Path path = Paths.get(fileName);
        byte[] bytes = Files.readAllBytes(path);
        return bytes;
    }

    public static void saveRsaKeys(String fileName) {
        try {
            Map<String, Object> keys = getRSAKeys();
            PrivateKey privateKey = (PrivateKey) keys.get("private");
            PublicKey publicKey = (PublicKey) keys.get("public");

            savePrivateKey(privateKey, fileName + ".pub");
            savePublicKey(publicKey, fileName + ".pk");
        } catch (Exception e) {
            e.printStackTrace();
        }




    }
}

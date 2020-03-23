package com.suceesive.pgpdecryption;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PGPFileProcessor {
	
	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	
	private static final String ALGORITHM = "RSA";
	
	
	public String readInputFile(String filePath) {
		
		logger.info(PGPFileProcessor.class+"----readInputFile(String filePath)");
		
		StringBuilder contentBuilder = new StringBuilder();
	    try (BufferedReader br = new BufferedReader(new FileReader(filePath))) 
	    {
	 
	        String sCurrentLine;
	        while ((sCurrentLine = br.readLine()) != null) 
	        {
	            contentBuilder.append(sCurrentLine).append("\n");
	        }
	    } 
	    catch (IOException e) 
	    {
	        e.printStackTrace();
	    }
	    return contentBuilder.toString();
	}
	
	public void writeOutputFile(String decryptOutputText,String outputFile) throws IOException, NullPointerException {
		
		logger.info(PGPFileProcessor.class+"----writeOutputFile(String decryptOutputText,String outputFile)");
		
		Files.write( Paths.get(outputFile), decryptOutputText.getBytes());
	}
	
    public byte[] encrypt(byte[] publicKey, byte[] inputData)
            throws Exception {

    	logger.info(PGPFileProcessor.class+"----encrypt(byte[] publicKey, byte[] inputData)");
    	
        PublicKey key = KeyFactory.getInstance(ALGORITHM)
                .generatePublic(new X509EncodedKeySpec(publicKey));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedBytes = cipher.doFinal(inputData);

        return encryptedBytes;
    }

    public byte[] decrypt(byte[] privateKey, byte[] inputData)
            throws Exception {
    	
    	logger.info(PGPFileProcessor.class+"----decrypt(byte[] privateKey, byte[] inputData");
    	
        PrivateKey key = KeyFactory.getInstance(ALGORITHM)
                .generatePrivate(new PKCS8EncodedKeySpec(privateKey));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decryptedBytes = cipher.doFinal(inputData);

        return decryptedBytes;
    }
	

}

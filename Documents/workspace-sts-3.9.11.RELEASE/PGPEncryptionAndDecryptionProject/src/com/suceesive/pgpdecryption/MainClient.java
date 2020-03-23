package com.suceesive.pgpdecryption;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Properties;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.openpgp.PGPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MainClient {

	private static final Logger logger = LoggerFactory.getLogger(MainClient.class);
	
	public static void main(String[] args) throws IOException {
		try {
			PGPFileProcessor pgpFileProcessor = new PGPFileProcessor();
			
			Properties prop = ReadPropertiesFile.readPropertiesFile("info.properties");
			
			byte[] encryptedData = pgpFileProcessor.encrypt(MyPGPUtil.getPublicKey(prop.getProperty("pkey")), pgpFileProcessor.readInputFile(prop.getProperty("inputFile")).getBytes());
            
			logger.info("Encrypted Data "+new String(encryptedData));
			
			byte[] decryptedData = pgpFileProcessor.decrypt(MyPGPUtil.getPrivateKey(prop.getProperty("skey")), encryptedData);

			pgpFileProcessor.writeOutputFile(new String(decryptedData), prop.getProperty("outputFile")); 			
           			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}

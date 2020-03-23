package com.suceesive.pgpdecryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyPGPUtil {
	
	private static final Logger logger = LoggerFactory.getLogger(MyPGPUtil.class);

	public static PGPPublicKey readPublicKeyFile(String filePath) throws IOException, PGPException {
		
		logger.info(MyPGPUtil.class+"----readPublicKeyFile(String filePath)");
		
		InputStream in = new FileInputStream(filePath);
		InputStream fin = PGPUtil.getDecoderStream(in);
		PGPPublicKeyRingCollection pgpPkrc = new PGPPublicKeyRingCollection(fin);
		Iterator rIt = pgpPkrc.getKeyRings();
		while (rIt.hasNext()) {
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator kIt = kRing.getPublicKeys();
			while (kIt.hasNext()) {
				PGPPublicKey key = (PGPPublicKey) kIt.next();
				if (key.isEncryptionKey()) {
					return key;
				}
			}
		}
		throw new IllegalArgumentException("Can't find encryption key in key ring.");
	}

	protected static byte[] getPublicKey(String filePath)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, PGPException {
		logger.info(MyPGPUtil.class+"----getPublicKey(String filePath)");
		PGPPublicKey encKey = readPublicKeyFile(filePath);
		return new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider()).getPublicKey(encKey).getEncoded();
	}

	private static PGPSecretKey readSecretKey(String fileSecPath) throws IOException, PGPException {
		logger.info(MyPGPUtil.class+"----readSecretKey(String fileSecPath)");
		
		InputStream in = new FileInputStream(fileSecPath);
		in = PGPUtil.getDecoderStream(in);

		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in);

		//
		// we just loop through the collection till we find a key suitable for
		// encryption, in the real
		// world you would probably want to be a bit smarter about this.
		//
		PGPSecretKey key = null;

		//
		// iterate through the key rings.
		//
		Iterator rIt = pgpSec.getKeyRings();

		while (key == null && rIt.hasNext()) {
			PGPSecretKeyRing kRing = (PGPSecretKeyRing) rIt.next();
			Iterator kIt = kRing.getSecretKeys();

			while (key == null && kIt.hasNext()) {
				PGPSecretKey k = (PGPSecretKey) kIt.next();

				if (k.isSigningKey()) {
					key = k;
				}
			}
		}

		if (key == null) {
			throw new IllegalArgumentException("Can't find signing key in key ring.");
		}

		return key;
	}

	private static PGPPrivateKey extractPrivateKey(PGPSecretKey pgpSecKey, char[] passPhrase) throws PGPException {
		logger.info(MyPGPUtil.class+"----readSecretKey(String fileSecPath)");
		PGPPrivateKey privateKey = null;
		BcPGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();
		BcPBESecretKeyDecryptorBuilder secretKeyDecryptorBuilder = new BcPBESecretKeyDecryptorBuilder(
				calculatorProvider);
		PBESecretKeyDecryptor pBESecretKeyDecryptor = secretKeyDecryptorBuilder.build(passPhrase);

		try {
			privateKey = pgpSecKey.extractPrivateKey(pBESecretKeyDecryptor);
		} catch (PGPException e) {
			throw new PGPException("invalid privateKey passPhrase: " + String.valueOf(passPhrase), e);
		}

		return privateKey;
	}

	public static byte[] getPrivateKey(String filePath)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, PGPException {
		logger.info(MyPGPUtil.class+"----getPrivateKey(String filePath)");
		PGPSecretKey secKey = readSecretKey(filePath);
		return new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider())
				.getPrivateKey(extractPrivateKey(secKey, new String("aclsecure").toCharArray())).getEncoded();
	}

}

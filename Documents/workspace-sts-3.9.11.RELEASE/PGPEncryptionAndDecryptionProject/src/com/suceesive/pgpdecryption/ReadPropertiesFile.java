package com.suceesive.pgpdecryption;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ReadPropertiesFile {
	
	private static final Logger logger = LoggerFactory.getLogger(ReadPropertiesFile.class);
	
	public static Properties readPropertiesFile(String fileName) throws IOException {
	      InputStream is = null;
	      Properties prop = null;
	      try {
	    	  is = ReadPropertiesFile.class.getClassLoader().getResourceAsStream(fileName);
	         prop = new Properties();
	         prop.load(is);
	      } catch(FileNotFoundException fnfe) {
	         fnfe.printStackTrace();
	      } catch(IOException ioe) {
	         ioe.printStackTrace();
	      } finally {
	         is.close();
	      }
	      return prop;
	   }
}

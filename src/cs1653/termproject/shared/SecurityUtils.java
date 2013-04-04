package cs1653.termproject.shared;

import java.security.Key;
import java.util.Arrays;
import javax.crypto.Mac;

/**
 * SecurityUtils hosts the HMAC generation utilities used for communication across the file sharing system.
 * @author Sean and Matt
 *
 */
public class SecurityUtils {

	public static byte[] createHMAC(byte[] message, Key key){
		if(key == null || message == null){
			return null;
		}

		try {
			Mac mac = Mac.getInstance(key.getAlgorithm());
			mac.init(key);
			byte[] digest = mac.doFinal(message);
			return digest;
		} catch (Exception e){
			e.printStackTrace();
		}

		return null;			
	}

	public static boolean checkHMAC(byte[] message, byte[] hmac, Key key){
		try {
			Mac mac = Mac.getInstance(key.getAlgorithm());
			mac.init(key);
			byte[] digest = mac.doFinal(message);
			return Arrays.equals(digest, hmac);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}
}

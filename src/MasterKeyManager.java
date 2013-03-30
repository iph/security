import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Scanner;

import org.bouncycastle.util.encoders.Hex;

/**
 * This class is used for dealing with the Master Files Keys. 
 * It provides information on how many keys there are, and offers the ability to generate more.
 * @author Matt
 *
 */
public class MasterKeyManager {
	
	private static ArrayList<byte[]> keyList;
	
	public static void main(String[] args) {
		System.out.println("Welcome to the Master Key Manager!");
		System.out.print("Please choose from the following options:");
		System.out.print(
		"\n1) Print the number of keys and the keys themselves" + 
		"\n2) Add a new key" + 
		"\n3) Do both 1 and 2" + 
		"\nOr any other key to quit\n");
		
		Scanner in = new Scanner(System.in);
		
		int choice = in.nextInt();
		
		switch (choice) {
			case 1:
				if (loadKeys()) {
					printKeyInfo();
				}
				break;
			case 2:
				if (!loadKeys()) {
					keyList = new ArrayList<byte[]>();
				}
				addKey();
				writeKeys();
				break;
			case 3:
				if (loadKeys()) {
					printKeyInfo();
				}
				else {
					keyList = new ArrayList<byte[]>();
				}
				addKey();
				writeKeys();
				break;
			default:
		}
		
		in.close();
	}
	
	private static byte[] generateBytes() {
		// Create a secure random number generator
		SecureRandom rand = new SecureRandom();
		
		byte[] secureBytes = new byte[256];
		
		rand.nextBytes(secureBytes);
		
		return secureBytes;
	}
	
	private static boolean loadKeys() {
		String keyFile = "MasterKeyList.bin";
		boolean returnValue = false;
		
		FileInputStream fis;
		
		try {
			fis = new FileInputStream(keyFile);
			ObjectInputStream keyStream = new ObjectInputStream(fis);
			keyList = (ArrayList<byte[]>)keyStream.readObject();
			fis.close();
			returnValue = true;
		} catch (FileNotFoundException e) {
			System.out.println("There is no key file yet!");
		} catch (Exception e) {
			System.out.println("keyFile issue!");
			e.printStackTrace();
		}
		
		return returnValue;
	}
	
	private static void writeKeys() {
		System.out.println("Writing the key list to the file...");
		String keyFile = "MasterKeyList.bin";
		
		FileOutputStream fos;
		
		try {
			fos = new FileOutputStream(keyFile);
			ObjectOutputStream keyStream = new ObjectOutputStream(fos);
			keyStream.writeObject(keyList);
			fos.close();
		} catch (Exception e) {
			System.out.println("keyFile issue!");
			e.printStackTrace();
		}
		
		System.out.println("Done!");
	}
	
	private static void printKeyInfo() {
		StringBuilder builder = new StringBuilder();
		
		builder.append("Key information:\nNumber of keys currently: " + keyList.size());
		
		if (keyList.size() > 0) {
			for (int i = 0; i < keyList.size(); i++) {
				builder.append("\nKey #" + i + ") ");
				builder.append(new String(Hex.encode(keyList.get(i))));
			}
		}
		
		System.out.println(builder.toString());
	}
	
	private static void addKey() {
		System.out.println("Adding a new key...");
		keyList.add(generateBytes());
		System.out.println("Done!");
	}
	
	public static void addKeyExternal() {
		keyList = new ArrayList<byte[]>();
		addKey();
		writeKeys();
	}
}

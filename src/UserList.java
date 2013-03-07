/* This list represents the users on the server */
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

	public class UserList implements java.io.Serializable {
		
		private static final long serialVersionUID = 7600343803563417992L;
		
		private HashMap<String, User> list = new HashMap<String, User>();
		
	    public synchronized boolean addUser(String username, String password)
		{
			User newUser = new User(password);
			// We want it to be null, that means there was no previous user, which is good and means nothing is broken.
			return (list.put(username, newUser) == null);
		}
		
		public synchronized boolean deleteUser(String username)
		{
			// We want it to be something other than null, meaning a user was deleted.
			return (list.remove(username) != null);
		}
		
	    public synchronized boolean checkUser(String username)
		{
			return list.containsKey(username);
		}

	    public synchronized boolean checkUserPassword(String username, String password){
	    	System.out.println(list.containsKey(username));
	    	System.out.println(list.get(username));
	    	return list.containsKey(username) && list.get(username).checkPassword(password);
	    }
		
		public synchronized HashSet<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}
		
		public synchronized HashSet<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}
		
		public synchronized boolean addGroup(String user, String groupname)
		{
			return list.get(user).addGroup(groupname);
		}
		
		public synchronized boolean removeGroup(String user, String groupname)
		{
			return list.get(user).removeGroup(groupname);
		}
		
		public synchronized boolean addOwnership(String user, String groupname)
		{
			return list.get(user).addOwnership(groupname);
		}
		
		public synchronized boolean removeOwnership(String user, String groupname)
		{
			return list.get(user).removeOwnership(groupname);
		}
		
		public synchronized void removeGroupFromAllUsers(String groupname) {
			for (User user : list.values()) {
				user.removeGroup(groupname);
			}
		}
		
		public synchronized void removeOwnershipFromAllUsers(String groupname) {
			for (User user : list.values()) {
				user.removeOwnership(groupname);
			}
		} 
		
	
	class User implements java.io.Serializable {
		
		private static final long serialVersionUID = -6699986336399821518L;
		private String password;
		private String salt;
		private HashSet<String> groupSet;
		private HashSet<String> ownershipSet;
		
		public User()
		{
			groupSet = new HashSet<String>();
			ownershipSet = new HashSet<String>();
		}

		public User(String password){
		    this();
			try{
			    Security.addProvider(new BouncyCastleProvider());
			    byte [] saltByte = new byte[32];
			    SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
			    rng.nextBytes(saltByte);
			    salt = new String(saltByte);
			    String saltedPassword = password + salt;
			    MessageDigest mda = MessageDigest.getInstance("SHA-512", "BC");
			    byte [] digest = mda.digest(saltedPassword.getBytes());
			    this.password = new String(digest);
			}
			catch(Exception e){
				e.printStackTrace();
			}


		}

		public HashSet<String> getGroups()
		{
			return groupSet;
		}
		
		public HashSet<String> getOwnership()
		{
			return ownershipSet;
		}
		
		public boolean addGroup(String group)
		{
			return groupSet.add(group);
		}
		
		public boolean removeGroup(String group)
		{
			// Not sure if you remove from an empty set what happens
			if (groupSet.isEmpty()) {
				return false;
			}
			
			return groupSet.remove(group);
		}
		
		public boolean addOwnership(String group)
		{
			return ownershipSet.add(group);
		}
		
		public boolean removeOwnership(String group)
		{
			// Not sure if you remove from an empty set what happens
			if (groupSet.isEmpty()) {
				return false;
			}
			
			return groupSet.remove(group);
		}
		public String toString(){
			System.out.println(password);
			return "";
		}
		
		public boolean checkPassword(String plaintextPassword){
		    Security.addProvider(new BouncyCastleProvider());
			try {
				
			    String saltedPassword = plaintextPassword + salt;
			    MessageDigest mda = MessageDigest.getInstance("SHA-512", "BC");
			    byte [] digest = mda.digest(saltedPassword.getBytes());
			    return this.password.equals(new String(digest));
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return false;
			
		}
		
	}
	
}	

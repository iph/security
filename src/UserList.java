/* This list represents the users on the server */
import java.util.*;

	public class UserList implements java.io.Serializable {
		
		private static final long serialVersionUID = 7600343803563417992L;
		
		private HashMap<String, User> list = new HashMap<String, User>();
		
		public synchronized boolean addUser(String username)
		{
			User newUser = new User();
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
		
		private static final long serialVersionUID = -6699986336399821598L;
		
		private HashSet<String> groupSet;
		private HashSet<String> ownershipSet;
		
		public User()
		{
			groupSet = new HashSet<String>();
			ownershipSet = new HashSet<String>();
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
		
	}
	
}	

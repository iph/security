import java.util.*;

public class GroupList implements java.io.Serializable{	
	
	private static final long serialVersionUID = 8472291674451045025L;
	
	private HashMap<String, Group> list;

	public GroupList(){
		list = new HashMap<String, Group>();
	}

	public synchronized boolean addGroup(String groupname){
		Group newGroup = new Group();
		return (list.put(groupname, newGroup) != null);
	}

	public synchronized boolean deleteGroup(String groupname){
		return (list.remove(groupname) != null);
	}

	public synchronized boolean checkGroup(String groupname){
		return list.containsKey(groupname);
	}

	public synchronized boolean isOwner(String groupname, String user){
		return checkGroup(groupname) && list.get(groupname).isOwner(user);
	}
	
	public synchronized boolean isMember(String groupname, String user){
		return checkGroup(groupname) && list.get(groupname).isMember(user);
	}

	public synchronized Set<String> getMembers(String groupname){
		return list.get(groupname).getUsers();
	}

	public synchronized Set<String> getOwners(String groupname){
		return list.get(groupname).getOwners();
	}

	public synchronized boolean removeMember(String groupname, String user){
		if ((list.containsKey(groupname)) && (list.get(groupname).isMember(user))) {
			return list.get(groupname).removeUser(user);
		}
		else {
			return false;
		}
	}
	
	public synchronized boolean removeOwner(String groupname, String user){
	    if ((list.containsKey(groupname)) && (list.get(groupname).isOwner(user))) {
		    return list.get(groupname).removeOwner(user);
	    }
	    else {
		    return false;
	    }
	}

	public synchronized boolean addMember(String groupname, String user){
		return list.get(groupname).addUser(user);	
	}

	public synchronized boolean addOwner(String groupname, String user){
		return list.get(groupname).addOwner(user);
	}
	
	public synchronized boolean removeAllMembers(String groupname) {
		if (list.containsKey(groupname)) {
			list.get(groupname).removeAllUsers();
			return true;	
		}
		
		return false;
	}
	
	public synchronized boolean isOnlyOwner (String groupname, String username) {
		return checkGroup(groupname) && list.get(groupname).isOnlyOwner(username);
	}
}

class Group implements java.io.Serializable{
	
	private static final long serialVersionUID = -8293900391158968283L;
	
	Set<String> users;
	Set<String> owners;	

	public Group(){
		users = new HashSet<String>();
		owners = new HashSet<String>();
	}

	public Set<String> getUsers(){
		return users;
	}

	public Set<String> getOwners(){
		return owners;
	}

	public boolean addUser(String username){
		return users.add(username);
	} 

	public boolean addOwner(String username){
		return owners.add(username);
	}

	public boolean removeUser(String username){
		return users.remove(username);
	}
	public boolean removeOwner(String username) {
		return owners.remove(username);
	}
	
	public void removeAllUsers() {
		users.clear();
	}

	public boolean isOwner(String username){
		return owners.contains(username);
	}
	
	public boolean isMember(String username){
		return users.contains(username);
	}
	
	public boolean isOnlyOwner(String username) {
		if ((owners.contains(username)) && (owners.size() == 1)) {
			return true;
		}
		else {
			return false;
		}
	}
}

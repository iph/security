import java.util.*;

public class GroupList implements java.io.Serializable{	
	
	private static final long serialVersionUID = 8472291674451045025L;
	
	private HashMap<String, Group> list;

	public GroupList(){
		list = new HashMap<String, Group>();
	}

	public synchronized void addGroup(String groupname){
		Group newGroup = new Group();
		list.put(groupname, newGroup);
	}

	public synchronized void deleteGroup(String groupname){
		list.remove(groupname);
	}

	public synchronized boolean checkGroup(String groupname){
		return list.containsKey(groupname);
	}

	public synchronized boolean isOwner(String groupname, String user){
		return checkGroup(groupname) && list.get(groupname).getOwners().contains(user);
	}

	public synchronized Set<String> getMembers(String groupname){
		return list.get(groupname).getUsers();
	}

	public synchronized Set<String> getOwners(String groupname){
		return list.get(groupname).getOwners();
	}

	public synchronized void removeMember(String groupname, String user){
		if(list.get(groupname).isUser(user)){
			list.get(groupname).removeUser(user);
		}
		else{
			deleteGroup(groupname);
		}
	}

	public synchronized void addMember(String groupname, String user){
		list.get(groupname).addUser(user);	
	}

	public synchronized void addOwner(String groupname, String user){
		list.get(groupname).addOwner(user);
	}
}

class Group implements java.io.Serializable{
	
	/**
	 * 
	 */
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

	public void addUser(String username){
		users.add(username);
	} 

	public void addOwner(String username){
		owners.add(username);
	}

	public void removeUser(String username){
		users.remove(username);
	}

	public boolean isUser(String username){
		return users.contains(username);
	}

	public boolean isOwner(String username){
		return owners.contains(username);
	} 
}
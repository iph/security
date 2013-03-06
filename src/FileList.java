/* T
 * his list represents the files on the server */
import java.util.*;


	public class FileList implements java.io.Serializable {
		
	/*Serializable so it can be stored in a file for persistence */
	private static final long serialVersionUID = -8911161283900260136L;
	//private ArrayList<ShareFile> list;
	// Have to use a map instead of a set because files are tracked by path, not by ShareFile instance
	private HashMap<String,ShareFile> fileMap;
	
	public FileList()
	{
		//list = new ArrayList<ShareFile>();
		fileMap = new HashMap<String,ShareFile>();
	}
	
	public synchronized void addFile(String owner, String group, String path)
	{
		ShareFile newFile = new ShareFile(owner, group, path);
		//list.add(newFile);
		fileMap.put(path, newFile);
	}
	
	public synchronized void removeFile(String path)
	{
		//for (int i = 0; i < list.size(); i++) {
		//	if (list.get(i).getPath().compareTo(path)==0) {
		//		list.remove(i);
		//	}
		//}
		fileMap.remove(path);
	}
	
	public synchronized boolean checkFile(String path)
	{
		//for (int i = 0; i < list.size(); i++) {
		//	if (list.get(i).getPath().compareTo(path)==0) {
		//		return true;
		//	}
		//}
		return fileMap.containsKey(path);
		//return false;
	}
	
	public synchronized ArrayList<ShareFile> getFiles()
	{
		ArrayList<ShareFile> list = new ArrayList<ShareFile>(fileMap.values());
		Collections.sort(list);
		return list;			
	}
	
	public synchronized ShareFile getFile(String path)
	{
		//for (int i = 0; i < list.size(); i++) {
		//	if (list.get(i).getPath().compareTo(path)==0) {
		//		return list.get(i);
		//	}
		//}
		return fileMap.get(path);
		//return null;
	}
}	

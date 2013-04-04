package cs1653.termproject.servers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;

public class FileList implements java.io.Serializable {
	private static final long serialVersionUID = -8911161283900260136L;
	// Have to use a map instead of a set because files are tracked by path, not by ShareFile instance
	private HashMap<String,ShareFile> fileMap;

	public FileList() {
		fileMap = new HashMap<String,ShareFile>();
	}

	public synchronized void addFile(String owner, String group, String path, byte[] iv, byte[] seed, int keyId) {
		ShareFile newFile = new ShareFile(owner, group, path, iv, seed, keyId);
		fileMap.put(path, newFile);
	}

	public synchronized void removeFile(String path) {
		fileMap.remove(path);
	}

	public synchronized boolean checkFile(String path) {
		return fileMap.containsKey(path);
	}

	public synchronized ArrayList<ShareFile> getFiles() {
		ArrayList<ShareFile> list = new ArrayList<ShareFile>(fileMap.values());
		Collections.sort(list);
		return list;			
	}

	public synchronized ShareFile getFile(String path) {
		return fileMap.get(path);
	}
}	

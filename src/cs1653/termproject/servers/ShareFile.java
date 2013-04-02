package cs1653.termproject.servers;
public class ShareFile implements java.io.Serializable, Comparable<ShareFile> {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6699986336399821598L;
	private String group;
	private String path;
	private String owner;
	private byte[] seed;
	private byte[] iv;
	private int keyId;
	public ShareFile(String _owner, String _group, String _path, byte[] _iv, byte[] _seed, int _keyId) {
		group = _group;
		owner = _owner;
		path = _path;
		keyId = _keyId;
		seed = _seed;
		iv = _iv;
	}
	
	public String getPath()
	{
		return path;
	}
	
	public String getOwner()
	{
		return owner;
	}
	
	public String getGroup() {
		return group;
	}
	
	public byte[] getSeed(){
		return seed;
	}
	
	public int getKeyId(){
		return keyId;
	}
	
	public byte[] getIV(){
		return iv;
	}
	public int compareTo(ShareFile rhs) {
		if (path.compareTo(rhs.getPath())==0)return 0;
		else if (path.compareTo(rhs.getPath())<0) return -1;
		else return 1;
	}
	
	
}	

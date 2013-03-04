import org.bouncycastle.util.Arrays;

public class Payload implements java.io.Serializable {
	
	private static final long serialVersionUID = 100L;
	
	byte[] encryptedData;
	
	public Payload(byte[] data) {
		encryptedData = Arrays.copyOf(data, data.length);
	}
}

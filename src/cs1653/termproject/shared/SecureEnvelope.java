package cs1653.termproject.shared;

import java.util.Arrays;

/**
 * SecureEnvelope extends Envelope and is used for encrypted communication. 
 * @author Sean and Matt
 *
 */
public class SecureEnvelope extends Envelope {

	private static final long serialVersionUID = 200L;
	private byte[] payload; // Encrypted data in byte[] form
	private byte[] ivSpec; // IvParameterSpec is not serializable, thus a byte[] is used
	private byte[] hmac; // HMAC of the payload
	
	public SecureEnvelope(String text) {
		super(text);
		payload = null;
		ivSpec = null;
		hmac = null;
	}
	
	public SecureEnvelope() {
		super();
		payload = null;
		ivSpec = null;
		hmac = null;
	}
	
	public void setPayload(byte[] _payload) {
		payload = Arrays.copyOf(_payload, _payload.length);
	}
	
	public byte[] getPayload() {
		return payload;
	}
	
	public void setIV(byte[] _ivSpec) {
		ivSpec = Arrays.copyOf(_ivSpec, _ivSpec.length);
	}
	
	public byte[] getIV() {
		return ivSpec;
	}
	
	public void setHMAC(byte[] _hmac){
		hmac = _hmac;
	}
	
	public byte[] getHMAC(){
		return hmac;
	}
}

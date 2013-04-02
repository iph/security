import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

public class SecureEnvelope extends Envelope {

	private static final long serialVersionUID = 200L;
	private byte[] payload;
	// IvParameterSpec is not serializable, thus a byte[] is used
	private byte[] ivSpec;
	private byte[] hmac;
	
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
		//return Arrays.copyOf(payload, payload.length);
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

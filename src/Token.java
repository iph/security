import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.*;

public class Token implements UserToken, Serializable {
	private static final long serialVersionUID = 1337L;
	private String issuer, subject;
	private HashSet<String> groups;
	private byte[] signature;

	public Token(String issuer_, String subject_, HashSet<String> groups_){
		issuer = issuer_;
		subject = subject_;
		groups = groups_;
	}

	public Token(String issuer_, String subject_, HashSet<String> groups_, byte[] signature_) {
		this(issuer_, subject_, groups_);
		signature = Arrays.copyOf(signature_, signature_.length);
	}

	public String getIssuer() {
		return issuer;
	}

	public void setSignature(byte[] signature_) {
		signature = Arrays.copyOf(signature_, signature_.length);
	}

	public byte[] getSignature() {
		return signature;
	}

	public byte[] toByteArray() {
		byte[] returnBytes = null;
				
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = null;
		try {
			out = new ObjectOutputStream(bos);   
			out.writeObject(issuer);
			out.writeObject(subject);
			out.writeObject(groups);
			returnBytes = bos.toByteArray();
			out.close();
			bos.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return returnBytes;
	 }


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject(){

    	return subject;
    }


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public HashSet<String> getGroups(){

    	return groups;
    }
    
    public String toString() {
    	StringBuilder builder = new StringBuilder();
    	
    	builder.append("Token Information:" +
    			"\nIssuer: " + issuer + 
    			"\nSubject: " + subject +
    			"\nGroups: " + groups);
    	
    	return builder.toString();
    }
}
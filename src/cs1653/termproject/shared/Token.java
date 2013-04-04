package cs1653.termproject.shared;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.*;

/**
 * Implementation of the UserToken interface.
 * @author Sean and Matt
 *
 */
public class Token implements UserToken, Serializable {
	private static final long serialVersionUID = 1337L;
	private String issuer; // The issuer of the token
	private String subject; // The subject (user/client) of the token
	private int threadID; // Server-side threadID
	private HashSet<String> groups; // Groups the user is a member of
	private byte[] signature; // Signed hash of the token

	public Token(String issuer_, String subject_, HashSet<String> groups_){
		issuer = issuer_;
		subject = subject_;
		groups = groups_;
	}

	public Token(String issuer_, String subject_, HashSet<String> groups_, int threadID_) {
		this(issuer_, subject_, groups_);
		threadID = threadID_;
	}

	public String getIssuer() {
		return issuer;
	}

	public int getThreadID() {
		return threadID;
	}

	public void setSignature(byte[] signature_) {
		signature = Arrays.copyOf(signature_, signature_.length);
	}

	public byte[] getSignature() {
		return signature;
	}

	/**
	 * Converts the issuer, subject, group membership, and threadID into a byte[].
	 * This is used since Serializing may be unpredictable otherwise.
	 * @return byte[] containing the byte representation of the data.
	 */
	public byte[] toByteArray() {
		byte[] returnBytes = null;

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = null;
		try {
			out = new ObjectOutputStream(bos);   
			out.writeObject(issuer);
			out.writeObject(subject);
			out.writeObject(groups);
			out.writeObject(threadID);
			returnBytes = bos.toByteArray();
			out.close();
			bos.close();
		} catch (Exception e) {
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

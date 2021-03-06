package email;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import com.google.api.services.gmail.model.Message;

import encrypt.EncryptedIndex;
import encrypt.structures.EncryptedSystem;

public final class Upload {
	/**
     * Uploads an encrypted system ignoring keys but 
     * including EncryptedState
     * @param handler 
     * @param system
     * @return
     */
	public static boolean uploadEncryptedSystem(EmailHandler handler, EncryptedSystem system) {
		// TODO Auto-generated method stub
		return false;
	}
	
	/**
	 * Uploads an EncryptedIndex
	 * @throws IOException 
	 */
	public static boolean uploadEncryptedIndex(EmailHandler handler, EncryptedIndex index) throws IOException {
		return uploadFiles(handler, index.FILEENCRYPTED) && uploadFiles(handler, index.KEYWORDENCRYPTED);
	}
	
	/**
	 * Uploads the state for an EncryptedIndex
	 * @throws IOException 
	 */
	public static boolean uploadState(EmailHandler handler, EncryptedIndex index) throws IOException {
		if (index.STATE == null) {
			return false;
		}
		
		String hmac = new String(Base64.getEncoder().encode(index.STATE[0]));
		String enc = new String(Base64.getEncoder().encode(index.STATE[1]));
		
		return Upload.uploadFile(handler,
				new String(Base64.getEncoder().encode("STATE".getBytes())),
				hmac + "||" + enc);
	}
	
	/**
	 * Uploads a file and its keywords
	 * @param handler : email, service tuple
	 * @param keywords : keywords for the subject line
	 * @param fileContents : file to include in the body
	 * @return true on success
	 * @throws IOException
	 */
	public static boolean uploadKeywordsFile(EmailHandler handler, List<String> keywords, String fileContents) throws IOException {
		String subject = "";
		for (String key : keywords) {
			subject += key + " ";
		}
		return Upload.uploadFile(handler, subject, fileContents);
	}
	
	/**
	 * Uploads a file with its name
	 * @param handler
	 * @param filename
	 * @param fileContents
	 * @return true on success
	 * @throws IOException
	 */
	public static boolean uploadFile(EmailHandler handler, String filename, String fileContents) throws IOException {
		try {
			Message email = Upload.createEmail(handler.EMAIL, filename, fileContents);
			handler.SERVICE.users().messages().send("me", email).execute();
		} catch (MessagingException e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}
	
	/**
	 * Uploads multiple files
	 * @param handler
	 * @param files
	 * @return true on success
	 * @throws IOException
	 */
	public static boolean uploadFiles(EmailHandler handler, Map<String, String> files) throws IOException {
		for (Map.Entry<String, String> file : files.entrySet()) {
			if (!uploadFile(handler, file.getKey(), file.getValue())) {
				return false;
			}
		}
		
		return true;
	}
	
    /**
     * Create a MimeMessage using the parameters provided.
     *
     * @param to email address of the receiver
     * @param from email address of the sender, the mailbox account
     * @param subject subject of the email
     * @param bodyText body text of the email
     * @return the Message to be used to send email
     * @throws MessagingException
     * @throws IOException 
     */
    private static Message createEmail(String address, String subject, String bodyText) 
    		throws MessagingException, IOException {
        Properties props = new Properties();
        Session session = Session.getDefaultInstance(props, null);

        MimeMessage email = new MimeMessage(session);

        email.setFrom(new InternetAddress(address));
        email.addRecipient(javax.mail.Message.RecipientType.TO,
                new InternetAddress(address));
        email.setSubject(subject);
        email.setText(bodyText);
        
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        email.writeTo(buffer);
        byte[] bytes = buffer.toByteArray();
        String encodedEmail = com.google.api.client.util.Base64.encodeBase64URLSafeString(bytes);
        Message message = new Message();
        message.setRaw(encodedEmail);
        
        return message;
    }

}

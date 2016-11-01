package email;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import com.google.api.client.util.Base64;
import com.google.api.services.gmail.model.Message;

public final class Upload {
	
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
    private static Message createEmail(String address,
                                          String subject,
                                          String bodyText) throws MessagingException, IOException {
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
        String encodedEmail = Base64.encodeBase64URLSafeString(bytes);
        Message message = new Message();
        message.setRaw(encodedEmail);
        
        return message;
    }

}

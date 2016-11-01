package email;

import java.io.IOException;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Profile;

public class EmailHandler {
	public final Gmail SERVICE;
	public final String EMAIL;
	
	public EmailHandler() throws IOException {
		this.SERVICE = Authenticate.getGmailService();
		Profile profile = this.SERVICE.users().getProfile("me").execute();
		this.EMAIL = profile.getEmailAddress();
	}

}

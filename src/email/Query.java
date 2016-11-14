package email;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.ListMessagesResponse;
import com.google.api.services.gmail.model.Message;

public final class Query {
	
	/**
	   * List all Messages of the user's mailbox matching the query.
	   *
	   * @param service Authorized Gmail API instance.
	   * @param query String used to filter the Messages listed.
	   * @throws IOException
	   */
	  private static List<String> listMessagesMatchingQuery(EmailHandler handler, String query) throws IOException {
	    /** Me indicates the authenticated user **/
		String userId = "me";
	    Gmail service = handler.SERVICE;
		ListMessagesResponse response = service.users().messages().list(userId).setQ(query).execute();

	    List<Message> messages = new ArrayList<Message>();
	    while (response.getMessages() != null) {
	      messages.addAll(response.getMessages());
	      if (response.getNextPageToken() != null) {
	        String pageToken = response.getNextPageToken();
	        response = service.users().messages().list(userId).setQ(query)
	            .setPageToken(pageToken).execute();
	      } else {
	        break;
	      }
	    }
	    
	    List<String> toreturn = new ArrayList<String>();
	    for (Message message : messages) {
	    	toreturn.add(service.users().messages().get(userId, message.getId()).execute().getPayload().getBody().getData());
	    }
	    return toreturn;
	  }
	  
	  /**
	   * Gets all the messages that match a token
	   * * @throws IOException 
	   */
	  public static List<String> queryToken(EmailHandler handler, String token) throws IOException {
		  return Query.listMessagesMatchingQuery(handler, "subject:" + token);
	  }
	  
	  /**
	   * Queries multiple tokens
	   * @param handler : service and email tuple
	   * @param tokens : query tokens
	   * @return Emails that match
	   * @throws IOException 
	   */
	  public static List<String> queryTokens(EmailHandler handler, List<String> tokens) throws IOException {
		  List<String> messages = new ArrayList<String>();
		  for (String token : tokens) {
			  messages.addAll(Query.queryToken(handler, token));
		  }
		  
		  return messages;
	  }

}

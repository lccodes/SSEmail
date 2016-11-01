package test;

import java.io.IOException;

import email.EmailHandler;
import email.Upload;

public class EmailTests {
	public static void main(String[] args) throws IOException {
        EmailHandler handler = new EmailHandler();
        
        Upload.uploadFile(handler, "The email part works", "Hi Seny and Tarik, \n This is one of the tests in my testsuite for the library"
        		+ " that we spoke of yesterday. I've gotten the searching and insertion functionality working with a new gmail account that"
        		+ " I setup. The methods I wrote can be applied to anyone's gmail account simply by tweaking the config file. If you got this"
        		+ " email, which I suspect you did, then I am ready to start on the crypto side of the project. \n Cheers,\nLuke\n"
        		+ "PS. The method call to send this email to you is one line. :)");
    }

}

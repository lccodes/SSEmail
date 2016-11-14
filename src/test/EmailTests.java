package test;

import java.io.IOException;

import email.EmailHandler;
import email.Upload;

public class EmailTests {
	public static void main(String[] args) throws IOException {
        EmailHandler handler = new EmailHandler();
        
        Upload.uploadFile(handler, "Test", "Test");
    }

}

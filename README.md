# SSEmail

## Overview
SSEmail is an implementation of a structured encryption SSE scheme using Gmail as the legacy server. The library is divided 
into the scheme implementation and the server implementation. This means that anyone can add additional backends such as Github, 
Yahoo, and Hotmail without any cryptography knowledge. 

## API
The library offers two sets of APIs: one for the forward secure implementation and one for a more naive implementation. They
are named FSTools and SimpleTools respectively.

The key methods are:
  - createSearchableInbox which accepts three Salts and the path to the directory to be encrypted. 
      This method automatically opens a Google authentication link in the browser where you can select which 
      account to use for the inbox as the backend storage system. For the forward secure scheme, the method
      will automatically download and utilize the state stored in that inbox or will create an empty state
      that it will then store in the inbox.
      Salt is a class that lets you create, store, and open salts for cryptographic keys. You can provide the 
      path to a salt that you have generated independently or generate your own salts using the static methods 
      in the Salt class. This method requires a Salt for the psuedo-random function, the AES function, and
      the authenticated encryption function in that order.
  - queryPlaintextToken which accepts three Salts and the plaintext token. 
      The Salts obviously need to match the ones used in construction. The method will provide the same
      Google authentication link as above unless the token is still saved from an earlier run. The method
      returns all files that match the token decrypted. 
      
## Implementation
### Forward Secure Scheme
### EncryptedIndex
### Upload
### Query

# SSEmail

## Overview
SSEmail is an implementation of a structured encryption SSE scheme using Gmail as the legacy server. The library is divided 
into the scheme implementation and the server implementation. This means that anyone can add additional backends such as Github, 
Yahoo, and Hotmail without any cryptography knowledge. 

## API
The library offers two sets of APIs: one for the forward secure implementation and one for a more naive implementation. They
are named FSTools and SimpleTools respectively. They are located in the /search module.

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
  - queryPlaintextToken which accepts three Salts and the plaintext keyword. 
      The Salts obviously need to match the ones used in construction. The method will provide the same
      Google authentication link as above unless the token is still saved from an earlier run. The method
      returns all files that match the token decrypted. 
      
## Implementation
### Forward Secure Scheme
The scheme uses three distinct keys: k1, k2, and k3.
Files are stored as emails with the subject PRF(k1, filename) and the body ENC(k2, fileContents).
Each keyword is stored as an email with the subject PRF(k1, keyword || count) and the body ENC(k2, file1,file2,...,fileN).
The state is stored as an email with the subject STATE and the body AENC(k3, state)

The forward secure implementation uses a dictionary, state, that maps keywords to counts in order to partition the list 
of files associated with a given keyword into N different sets where N = state[keyword]. This allows each update to the index
to increment state[keyword] and associate the new files with an entirely new token PRF(keyword || N+1). Whenever a user wants 
to retrieve all files associated with keyword, the scheme requests PRF(keyword || 0) through PRF(keyword || state[keyword]) and 
aggregates the results after decrypting them. The server cannot tell that PRF(keyword || N) and PRF(keyword || N+1) all related. The state is stored
with authenticated encryption so that a malicious server cannot corrupt it without alerting the user.

### EncryptedIndex
The EncryptedIndex is a universal data structure that stores an encrypted index, prepared using an arbitrary scheme, that is
ready for uploading. The EncryptedIndex stores a keyword map that associates encrypted keywords to encrypted file lists, a 
file map that associates encrypted files to encrypted file contents, and an encrypted state which is a byte[][] of an HMAC
output and a AES encrypted serialized byte stream. Using this EncryptedIndex allows you to implement new schemes without
altering the backend upload and download methods at all. Implement a new factory class that produces an EncryptedIndex
using your scheme and then subclass FSTools to use your factory.

### Upload
Upload provides a generic series of storage methods. The methods operate on plaintexts but apply a keyed PRF to the
filename and AES encrypts file contents. Filename and file contents are just two arbitrary strings (i.e. keyword:
filelist, fileName:fileContents, state:State).
  - uploadFile accepts key1, key2, and a filename, which is stored as the subject, 
    and filecontents, which is stored as the body.
  - uploadFiles accepts key1, key2, and a Map\<String, String> and does the same over a key value store.
  - uploadState accepts key1, key3, and a Map\<String, Integer> and stores the authenticated encryption of the map.
 
Subclass Upload to have these methods point at a different storage method such as Yahoo or GitHub.

### Query
Query provides a generic series of download methods that mirror their Upload counterparts.
  - downloadFile accepts key1, key2, and a plaintext token. It returns the decrypted contents associated with that token.
  - downloadFiles accepts key1, key2, and a List\<String> of plaintext tokens. It returns the List\<String> decrypted contents
      associated with that each.
  - downloadState accepts key1 and key3, and returns a Map\<String, Integer> state.

Subclass Query to have these methods point at a different storage method such as Yahoo or GitHub.

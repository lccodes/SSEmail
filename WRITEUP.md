# SSEmail
SSEmail is a edit+ forward secure symmetric searchable encryption (SSE) scheme implemented using
Gmail as the outsourced server. The library exposes two fundamental API calls that allow for the
edit+ operation and the query operation. These are documented in the README. 

I built the library in modules so that it is extensible and easy to use.
## /email
I started by writing the email package, which is standalone and allows storage and querying a
Gmail account. It abstracts away authentication, autherization, uploading, and downloading so
that other modules can treat a Gmail account as a label value store without dealing with the
Gmail API. This module exposes Upload and Download capabilities on arbitrary strings.

## /upload && /query
I wrote an interface between the email backend and the encryption protocols that provides Upload 
and Query methods for the encryption schemes to use. These methods abstract out the email system
and allows anyone who wants to implement a new backend to directly plug into the existing /encryption
module without any modification.

## /encryption
I wrote two protocols that both produce an EncryptedIndex. (A data structure that you can read
about in the README.) The first is a simple scheme and the second is the edit+ forward secure
SSE scheme. The encryption module interfaces with /upload and /query so both schemes are
storage agnostic. Both schemes only use label value stores as their data structures, which allows
the abstraction to work. 

The three core data structures in the scheme are:
  - keyword -> fileList
  - fileName -> fileContents
  - "state" -> State
  
### Primitives
Each data structure is sent to the storage system encrypted. The protocol uses three keys; all of
them are stored as Salts and only converted to keys when a user enters their password at runtime
and the keys are only stored in local memory. The labels in each data structure are passed through 
a keyed hash so that they can be queried, and the values are all AES encrypted with a seperate key.
The state is stored with a deterministic label and an authenticated AES encryption for the State
itself. The keyed hash used is a secure HMAC implementation and the AES used is a secure implementation
of AES-256.

### Protocol
The state stores a count for each keyword that represents
how many (keyword -> fileList) entries that the specific keyword is partitioned into. This allows
a user to add additional files associated with an existing keyword by incrementing the state[keyword]
and adding a new (keyword || state[keyword] -> newFileList) entry into the storage system. Each
keyword concatenated with a count is easily rediscovverable for the user, but impossible to associate
with the other partitions for the storage system because the keyed hash makes them indistinguishable.

## Modifications
To implement a new storage system:
  1. Add a new /email module that exposes Upload and Download functionality.
  2. Subclass Upload and Query to point at your /email module.
  
To implement a new protocol:
  1. Add a new /encryption module that only requires Upload(label : string, contents : string) and 
     Query(label : string) -> contents : string.
  2. Use the upload method in /upload and the query method in /query.

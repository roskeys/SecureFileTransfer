# CSE Programming Assignment 2
## Secure File Transfer
Implemented in Jdk 8 (not support JDK 11 due to java.xml.bind (JAXB) - REMOVED)
### How to run the code:
#### For Confidentiality Protocol 1:
##### For server side: 
The Server will keep on running and listening to connection request.  
Using multi-thread to write the files to the disk, the server working thread will finish until writing finish.
**arg[0]: port (default 1234)**
~~~
javac ServerCP1.java && java ServerCP1
~~~

##### For client side:
Run with default port and default server
~~~
javac ClientCP1.java && java ClientCP1
~~~
The client will upload the files in sequence
**args:**
- arg[0]: port (default 1234)
- arg[1]: server (default localhost)
- arg[2-n]: Files to upload (default example.txt)
~~~
javac ClientCP1.java && java ClientCP1 1234 localhost file1 file2 file3
~~~
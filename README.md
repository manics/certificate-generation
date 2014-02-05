certificate-generation
======================

Notes on generating certificates from an internal CA

certificates.txt
----------------
Create a root certificate authority
Create an intermediate certificate for code-signing
Create an SSL server certificate

java-jar-sign.txt
-----------------
Use the code signing certificate previously obtained to sign a jar

java-jar-sign-openmicroscopy.txt
--------------------------------
Use the code signing certificate to sign the openmicroscopy webstart jars

java-jar-selfsign.txt
---------------------
Create a standalone self-signed certificate for signing a jar in case you don't want to create a root CA


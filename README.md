# VAULT
This is a POC which is based on the Enterprise CA certificates.
Both Server Side and Client Side need to have certificates installed(include private key and public key)
For example, you have a script that needs call VirusTotal's API, general the API KEY will be saved in a configure file in plain text or set a variable in the script in plain text.

step 1.  Use Server side certificate public key to encrypted the VirusTotal API KEY and send the Client side Certificate information such as CN, Serial Number, Issuer, Comment to the VAULT SERVER by using json format.

step 2.  The VAULT SERVER receives the request, it will use Server side certificate private key to decrypted the VirusTotal API KEY. Then by using the Client side Certificate information to query the CA and use the Client side Certificate public key to encrypt the VirusTotal API KEY and save it to a file. At the same time, a UUID will be generated as a unique index when you need to get the VirusTotal API KEY.

step 3.  Call the "/get-token/<uuid>" by using the UUID, the VAULT Server will return the encrypted value, the Client receives the encrypted data and use it's own Client side certificate private key to decrypt it and get the VirusTotal API KEY in plain text.

The transport process and saved file are always encrypted data, no worry about the HTTPS and data leaks.  

VaultServer.py includes the following APIs:
1.  http://ip-address:8443/get-vault-certificate   GET method

2.  http://ip-address:8443/new-token   POST method

3.  http://ip-address:8443/list-token   GET method

4.  http://ip-address:8443/get-token/<uuid>   GET method


# VaultServer.py 

please replace 
```
vault_certificate_thumbprint = "" 
```
with your own Server side certificate thumbprint value. 



Change the service is listening on IP or localhost and specific port.
```
app.run(host='0.0.0.0', port=8443)
```

Notice: I installed server side certificate in "LocalMachine", if you install the server side certificate in "currentuser", you need replace the path with "CurrentUser"
```
$cert = Get-ChildItem cert:\\LocalMachine\\My | Where-Object {{ $_.Thumbprint -like "{VAULT_CERTIFICATE_THUMBPRINT}" }} | Select-Object -First 1
```
------------------------------------------------------------------------

VaultClient.ps1 is an powershell example that display how to use these APIs, and you also can build a python version or use other languages which you are familiar with.

# VaultClient.ps1

please replace the following variables with your own value.
```
$API_URL = "http://yourhostname_or_IPAddress:8443"
$Client_Certificate_Thumbprint = ""
$uuid = ""
```
Notice: I installed client side certificate in "CurrentUser", if you install the client side certificate in "LocalMachine", you need replace the path with "LocalMachine"
```
$cert = Get-ChildItem cert:\CurrentUser\My | Where-Object { $_.SerialNumber -like ($RESPONSE | ConvertFrom-Json | ConvertFrom-Json)[0].'Serial Number' } | Select-Object -First 1
```


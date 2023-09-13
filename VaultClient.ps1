$API_URL = "http://yourhostname_or_IPAddress:8443"
$Client_Certificate_Thumbprint = ""
$uuid = ""

Write-Output "***** TEST VAULT API /list-token *****`n"
$url = "$($API_URL)/list-token"
$response = Invoke-WebRequest -Uri $url -Method Get
Write-Output $response.content | ConvertFrom-Json
Write-Output "-------------------------------------------------------------------------`n"
Write-Output "`n`n"


Write-Output "***** TEST VAULT API /get-vault-certificate *****`n"
$url = "$($API_URL)/get-vault-certificate"
$certificatePath = "H:\vault\vault_certificate.crt"
# Use Invoke-WebRequest to get the raw content
$response = Invoke-WebRequest -Uri $url -Method Get
# Save the content to a file
[System.IO.File]::WriteAllBytes($certificatePath, $response.Content)
Write-Output "Certificate saved to $certificatePath"
Write-Output "-------------------------------------------------------------------------`n"
Write-Output "`n`n"


Write-Output "***** TEST VAULT API /new-token *****`n"
# Load the certificate
$vault_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$vault_cert.Import($certificatePath)
# Convert the string to bytes
$VIRUSTOTAL_API_KEY = Get-Content "H:\MonitorEmailSecurity\init.conf" | findstr VIRUSTOTAL_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$bytesToEncrypt = [System.Text.Encoding]::UTF8.GetBytes($VIRUSTOTAL_API_KEY)
# Encrypt the bytes using the public key from the certificate
$rsaProvider = $vault_cert.PublicKey.Key
$encryptedBytes = $rsaProvider.Encrypt($bytesToEncrypt, $true)
# Convert the encrypted bytes to Base64 string for easy viewing/transport
$encryptedBase64 = [Convert]::ToBase64String($encryptedBytes)
Write-Output $encryptedBase64
$cert = @(Get-ChildItem cert:\CurrentUser\My | Where-Object { $_.Thumbprint -like $Client_Certificate_Thumbprint })[0]
if ($cert.Subject -match 'CN=([^,]+)') {
    $CN = $matches[1]
}else { Write-Output "CN value not found." }
if ($cert.Issuer -match 'CN=([^,]+)') {
    $Issuer = $matches[1]
	$Issuer = certutil.exe | findstr "Config" | %{ $_.Split(':')[1]; } | foreach{ if($_.ToString().Trim() -match $Issuer) { $_.ToString().Trim() } }
}else { Write-Output "Issuer value not found." }
$SerialNumber = $cert.SerialNumber
$url = "$($API_URL)/new-token"
$HEADERS = @{ 'Content-Type' = "application/json" }
$BODY = @{ 'Comment' = "VirusTotal_API_KEY"; 'EncryptedData' = "$encryptedBase64"; 'CN' = "$CN"; 'SerialNumber' = "$SerialNumber"; 'Issuer' = "$Issuer" } | ConvertTo-Json
$RESPONSE = try { Invoke-RestMethod -Method 'POST' -Uri $url -Headers $HEADERS -Body $BODY } catch { $_.Exception.Response.StatusCode.Value__ }
Write-Output $RESPONSE | ConvertFrom-Json
Write-Output "-------------------------------------------------------------------------`n"
Write-Output "`n`n"


Write-Output "***** TEST VAULT API /get-token *****`n"
$url = "$($API_URL)/get-token/$($uuid)"
$response = Invoke-WebRequest -Uri $url -Method Get
if ($response.StatusCode -eq 200){
	Write-Output $response.content | ConvertFrom-Json | ConvertFrom-Json
	$cert = Get-ChildItem cert:\CurrentUser\My | Where-Object { $_.SerialNumber -like ($RESPONSE | ConvertFrom-Json | ConvertFrom-Json)[0].'Serial Number' } | Select-Object -First 1
	$encryptedBytes = [System.Convert]::FromBase64String(($RESPONSE | ConvertFrom-Json | ConvertFrom-Json)[0].'Encrypted Token')
	$rsaProvider = $cert.PrivateKey
	$decryptedBytes = $rsaProvider.Decrypt($encryptedBytes, $true)
	$decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
	Write-Output "The VirusTotal API Key is: $($decryptedString)"
}elseif($response.StatusCode -eq 204){
	Write-Output "The UUID $($uuid) record doesn't exist on the VAULT Server"
}else{
	Write-Output $response.StatusDescription
}


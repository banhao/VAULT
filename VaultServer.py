#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from flask import Flask, request, jsonify, make_response, send_file
import subprocess, base64, os, tempfile, json, random, string
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


vault_certificate_thumbprint = ""
app = Flask(__name__)


def generate_uuid(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))


def get_vault_certificate():
    try:
        # Invoke PowerShell command to retrieve the certificate
        ps_command = """
        $cert = Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -like "*CN=VAULT SERVER CERTIFICATE*" }
        if($cert) {
            $bytes = $cert[0].Export("Cert") 
            [Convert]::ToBase64String($bytes)
        }
        """
        certificate_base64 = subprocess.check_output(["powershell", "-Command", ps_command], stderr=subprocess.STDOUT, text=True)
        return certificate_base64
    except Exception as e:
        print(e)
        return None


def save_vault_certificate_to_file():
    try:
        certificate_base64 = get_vault_certificate()
        if not certificate_base64:
            return None

        # Decode from base64
        certificate_bytes = base64.b64decode(certificate_base64)

        # Create a temporary file to save the certificate
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, 'wb') as tmp:
            tmp.write(certificate_bytes)

        return path
    except Exception as e:
        print(e)
        return None


@app.route('/get-vault-certificate', methods=['GET'])
def get_vault_certificate_route():
    cert_file_path = save_vault_certificate_to_file()
    if cert_file_path:
        return send_file(cert_file_path, as_attachment=True, download_name='vault_certificate.crt', mimetype='application/x-x509-ca-cert')
    else:
        return jsonify({"error": "Unable to retrieve certificate"}), 500


@app.route('/new-token', methods=['POST'])
def new_token():
    # Ensure content type is JSON
    if not request.is_json:
        return jsonify({"error": "Content-type must be application/json"}), 400
    # Extract data from JSON
    data = request.json
    # Ensure required fields are present
    required_fields = ["Comment", "EncryptedData", "CN", "SerialNumber", "Issuer"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Field {field} is missing"}), 400
    # Extract the provided data
    Comment = data['Comment']
    encrypted_token = data['EncryptedData']
    CN = data['CN']
    SerialNumber = data['SerialNumber']
    Issuer = data['Issuer']
    uuid = generate_uuid(32)
    ps_command = """
$cert = Get-ChildItem cert:\\LocalMachine\\My | Where-Object {{ $_.Thumbprint -like "{VAULT_CERTIFICATE_THUMBPRINT}" }} | Select-Object -First 1
$encryptedBytes = [System.Convert]::FromBase64String("{ENCRYPTED_TOKEN}")
$rsaProvider = $cert.PrivateKey
$decryptedBytes = $rsaProvider.Decrypt($encryptedBytes, $true)
$decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
$decryptedString
""".format(VAULT_CERTIFICATE_THUMBPRINT=vault_certificate_thumbprint, ENCRYPTED_TOKEN=encrypted_token)
    TOKEN = (subprocess.check_output(["powershell", "-Command", ps_command], stderr=subprocess.STDOUT, text=True)).rstrip('\n')
    client_ip = request.remote_addr
    print("***" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " | Request from Client: ", client_ip, " | UUID: ",  uuid, " | Comment: ",  Comment, " | Client Cert Subject: ", CN, " | Client Cert Serial Number: ", SerialNumber, " | Client Cert Issuer: ", Issuer, " | Encrypted TOKEN by using VAULT Cert: ", encrypted_token)
    ps_command = """
$client_certificate = certutil.exe -view -config {ISSUER} -restrict "SerialNumber={SERIALNUMBER}"  -out "Binary Certificate" -silent | Select-Object -Skip 3
$certificate_name = $("{CN}" -replace(" ","_")) + ".crt"
$client_certificate | out-file $certificate_name
$client_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$client_cert.Import($certificate_name)
$bytesToEncrypt = [System.Text.Encoding]::UTF8.GetBytes("{TOKEN}")
$rsaProvider = $client_cert.PublicKey.Key
$encryptedBytes = $rsaProvider.Encrypt($bytesToEncrypt, $true)
$encryptedBase64 = [Convert]::ToBase64String($encryptedBytes)
$encryptedBase64
""".format(ISSUER=Issuer, SERIALNUMBER=SerialNumber, CN=CN, TOKEN=TOKEN)
    client_cert_encrypted_token = (subprocess.check_output(["powershell", "-Command", ps_command], stderr=subprocess.STDOUT, text=True)).rstrip('\n')
    
    print("***" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " | Request from Client: ", client_ip, " | UUID: ",  uuid, " | Comment: ",  Comment, " | Client Cert Subject: ", CN, " | Client Cert Serial Number: ", SerialNumber, " | Client Cert Issuer: ", Issuer, " | Encrypted TOKEN by using CLIENT Cert: ", client_cert_encrypted_token)
    data = {
    "UUID": uuid,
    "Comment": Comment,
    "CN": CN,
    "Serial Number": SerialNumber,
    "Issuer": Issuer,
    "Encrypted Token": client_cert_encrypted_token
    }
    try:
        with open('VAULT.json', 'r') as json_file:
            existing_data = json.load(json_file)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []
    if not isinstance(existing_data, list):
        existing_data = [existing_data]
    existing_data.append(data)
    with open('VAULT.json', 'w') as json_file:
        json.dump(existing_data, json_file, indent=4)
    json_string = json.dumps(data, indent=4)
    return jsonify(json_string), 201


@app.route('/list-token', methods=['GET'])
def list_token():
    if os.path.exists('VAULT.json') and os.path.getsize('VAULT.json') > 0:
        with open('VAULT.json', 'r') as file:
            content = file.read()
            return content, 200
    else:
        return jsonify({"error": "No record on the VAULT Server"}), 500


@app.route('/get-token/<uuid>', methods=['GET'])
def get_token(uuid):
    if uuid:
        with open('VAULT.json', 'r') as file:
            data = json.load(file)
        for i in range(len(data)):
            if data[i]['UUID'] == uuid:
                response_data = [{
                    "UUID": data[i]['UUID'],
                    "Comment": data[i]['Comment'],
                    "CN": data[i]['CN'],
                    "Serial Number": data[i]['Serial Number'],
                    "Issuer": data[i]['Issuer'],
                    "Encrypted Token": data[i]['Encrypted Token']
                }]
                json_string = json.dumps(response_data, indent=4)
                return jsonify(json_string), 200
        return jsonify({"Info": "Can NOT find the record for this UUID"}), 204
    else:
       return jsonify({"error": "Parameter UUID must be included"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443)

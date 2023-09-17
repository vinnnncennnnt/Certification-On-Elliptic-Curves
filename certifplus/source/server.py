#!/usr/bin/python3
import qrcode
import requests
import subprocess
from PIL import Image
from bottle import route, run, request, response
import base64
import zbarlight
from steganography import cacher , recuperer
import os
@route('/creation', method='POST')
def creation():
    print("[+] Getting request")
    # get certificate's data
    identity = request.forms.get('identite')
    title = request.forms.get('intitule_certif')

    #check the validity of parameters
    if identity == None or title == None or len(identity+title)>64:
        return "Not valid\n"
    
    #create the certificate block
    concatenated_data=identity+',' +title + ','
    if len(concatenated_data) > 64:
        print("[+] Error data length")
        return None
    
    #write the data in a txt file
    with open('/tmp/output.txt', 'w') as f:
        f.write(concatenated_data)
        f.close()

    print(f"[+] Generating signature, identity : {identity}, title :  {title} ")

    #hash the file with the private key
    result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', '../certificates/ecc.server.private.key.pem', '-out', '/tmp/output.sig', '/tmp/output.txt'], check=True)
    if result.returncode != 0:
        print("Error:", result.stderr.decode())
        return None
    
    #base64 the signature to convert it into ASCII data
    with open("/tmp/output.sig" , 'rb') as f:
        data = f.read()
        signature= base64.b64encode(data).decode("utf_8")
        f.close()
    print(f"[+] Requesting time stamp")

    #create the time stamp 
    result = subprocess.run(['openssl', 'ts', '-query', '-data', '/tmp/output.txt', '-no_nonce', '-sha512', '-cert', '-out', '/tmp/file.tsq'], check=True)
    if result.returncode != 0:
        print("Error:", result.stderr.decode())
        return None
    
    result = subprocess.run(['curl', '-H', 'Content-Type: application/timestamp-query', '--data-binary', '@/tmp/file.tsq', 'https://freetsa.org/tsr', '--output', '/tmp/file.tsr'], check=True)
    if result.returncode != 0:
        print("Error:", result.stderr.decode())
        return None
            
    
    """ with open("/tmp/file.tsq" , 'rb') as f:
        tsq_file=f.read() 
        f.close() """ 

    with open("/tmp/file.tsr" , 'rb') as f:
        tsr_file=f.read() 
        f.close() 

  

    print(f"[+] Requesting API image from Google ")

    #request the image from google API
    text = f'Attestation de  {title}| délivrée à ' + identity

    url = "http://chart.apis.google.com/chart"
    params = {
        'chst': 'd_text_outline',
        'chld': '000000|56|h|FFFFFF|b|{}'.format(text)
    }

    chart_response = requests.get(url, params=params)

    with open("/tmp/text.png", "wb") as f:
        f.write(chart_response.content)
        f.close()


    print(f"[+] Generating QR code ")
    # create QR code
    qr = qrcode.make(signature)
    qr.save('/tmp/qrcode.png')
    print(f"[+] Processing image ")
    # resize images
    Image.open('/tmp/qrcode.png').resize((210, 210)).save('/tmp/qrcode.png')
    Image.open('/tmp/text.png').resize((1000, 600)).save('/tmp/text.png')
    
    result=subprocess.run(["composite", "-gravity", "center", "/tmp/text.png", "../medias/fond_attestation.png", "/tmp/combinaison.png"], check=True)
    if result.returncode != 0:
        print("Error:", result.stderr.decode())
        return None
    
    #steganography
    print(f"[+] Encoding data into image ")
    stegano_data=concatenated_data + '0' * (64-len(concatenated_data))+ base64.b64encode(tsr_file).decode("utf_8") 

    image = Image.open("/tmp/combinaison.png")
    cacher(image , stegano_data)
    image.save("/tmp/combinaison.png")
    
    result=subprocess.run(["composite", "-geometry", "+1418+934", "/tmp/qrcode.png", "/tmp/combinaison.png", "/tmp/attestation.png"], check=True)
    if result.returncode != 0:
        print("Error:", result.stderr.decode())
        return None
    print(f"[+] Sending image ")
    
    response.set_header('Content-type', 'image/png')
    descripteur_fichier = open('/tmp/attestation.png','rb')
    contenu_fichier = descripteur_fichier.read()
    descripteur_fichier.close()
    return contenu_fichier

@route('/verification', method='POST')
def verification():
    request.files.get('image').save('/tmp/attestation_verif.png', overwrite=True)
    print("[+] Receiving image")
    image = Image.open('/tmp/attestation_verif.png')
    message_length = 7392

    print("[+] Getting data from  image")
    message = recuperer(image, message_length)
    tsr_file=base64.b64decode(message[64:])
    data = message.split(",")

    #write the data
    with open ("/tmp/received_data" , 'w') as f :
        f.write(data[0]+ ',' + data[1] + ',')
        f.close()

    # load to verify the timestamps
    with open ("/tmp/file_verif.tsr" , 'wb') as f :
        f.write(tsr_file)
        f.close()

    #verify if the time stamp certificates exist
    if not os.path.exists("../certificates/freetsa/tsa.crt") or not os.path.exists("../certificates/freetsa/cacert.pem"):
        try:
            print("[+] Downloading Free TSA certificates")
            # Download the files if they don't exist
            subprocess.run(["wget", "https://freetsa.org/files/tsa.crt", "-P" , "../certificates/freetsa"], check=True)
            subprocess.run(["wget", "https://freetsa.org/files/cacert.pem", "-P" , "../certificates/freetsa"], check=True)
            print("[+] Free TSA Download complete!")
        except subprocess.CalledProcessError as e:
            print("[+] Error: ", e)
            return "Server error, please try again later ...\n"
    
    print("[+] Verifiying the time stamp")
    try:
        result = subprocess.run(["openssl", "ts", "-verify", "-data", "/tmp/received_data", "-in", "/tmp/file_verif.tsr", "-CAfile", '../certificates/freetsa/cacert.pem', "-untrusted", '../certificates/freetsa/tsa.crt'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,check= True)
        print("[+] The time stamp   is valid")
    except :
        print("[+] The time stamp is not valid .. ")
        return "Not valid\n"


    if result.returncode !=0 :
        print("[+] Time Stamp not valid, exiting ...")
        return "Not valid\n"
    else :
        print("[+] Time Stamp valid")

    print("[+] Extracting the signature")
    
    # extract qrcode
    qr_code = image.crop((1418,934,1418+210,934+210))
    qr_code.save("/tmp/qr-code-verif.png", "PNG")
    qr_code = Image.open("/tmp/qr-code-verif.png")
    signature = zbarlight.scan_codes(['qrcode'], image)
    
    with open ("/tmp/signature.sig" , 'wb') as f :
        f.write(base64.b64decode(signature[0].decode("utf_8")))
        f.close()

    
    print("[+] Verifiying the signature")
    #verify the signature with the public key
    try:
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', '../certificates/ecc.public.key.pem', '-signature', '/tmp/signature.sig', '/tmp/received_data'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[+] The signature is valid")
    except :
        print("[+] The signature is not valid, exiting ...")
        return "Not Valid\n"


    response.set_header('Content-type', 'text/plain')
    return "Valid\n"



# start server
run(host='0.0.0.0', port=8080, debug=True)

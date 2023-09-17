# Certification-On-Elliptic-Curves


To create a new certificate run the command below (the [server.py](certifplus/source/server.py) must be running) :
```
curl -v -X POST -d 'identite=[author name]' -d 'intitule_certif=[certification name]' --cacert [path to the CA certificate] https://localhost:9000/creation --output [name of the certificate png file]
```

To verify your certificate run the command below (the [server.py](certifplus/source/server.py) must be running) :
```
curl -v -X POST  -F image=@[name of the certificate png file]  --cacert [path to the CA certificate] https://localhost:9000/verification
```

As an example, this script below is creating a certificate for ```toto``` named ```SecuTIC``` (script can be found at [verif_command.sh](verif_command.sh)) :
```
#!/bin/bash -x
curl -v -X POST -d 'identite=toto' -d 'intitule_certif=SecuTIC' --cacert ./certifplus/certificates/ecc.ca.cert.pem https://localhost:9000/creation --output image.png
curl -v -X POST  -F image=@image.png  --cacert ./certifplus/certificates/ecc.ca.cert.pem https://localhost:9000/verification
```

You could also check that the false certificate [image-falsifiee.png](image-falsifiee.png) (where hidden data has been corrupted) is not accepted as a valid certificate (more on this on the [RAPPORT.pdf](RAPPORT.pdf)).

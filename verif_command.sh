#!/bin/bash -x
curl -v -X POST -d 'identite=toto' -d 'intitule_certif=SecuTIC' --cacert ./certifplus/certificates/ecc.ca.cert.pem https://localhost:9000/creation --output image.png
curl -v -X POST  -F image=@image.png  --cacert ./certifplus/certificates/ecc.ca.cert.pem https://localhost:9000/verification

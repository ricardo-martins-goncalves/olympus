#!/bin/bash
read -p "Range(init): " ASSET_INIT
read -p "Range(end): " ASSET_END
URL=http://zeus.alpha.olympus.pt:8000/controller/delete/
COOKIES=cookies.txt
CURL_BIN="curl -s -c $COOKIES -b $COOKIES -e $URL"


SECONDS=0
i=$ASSET_INIT
while [ $i -le $ASSET_END ]
do
  $CURL_BIN $URL > /dev/null
  DJANGO_TOKEN="csrfmiddlewaretoken=$(grep csrftoken $COOKIES | sed 's/^.*csrftoken\s*//')"
  $CURL_BIN \
       -H "Content-Type: multipart/form-data" \
       -F "$DJANGO_TOKEN" \
       -F "user_id=$i"\
       -F "controller_id=1" \
       -F "file=@/home/zeus/API/scripts/data_controller_processor/admins_private_keys/controller_1.pem" \
       -X POST $URL
  rm $COOKIES
  i=$((i +1))
done
time=$SECONDS
cd ~/HLF/fabric/bin
export CORE_PEER_TLS_ENABLED=true
export FABRIC_CFG_PATH=../config
export CORE_PEER_LOCALMSPID="Alpha"
export CORE_PEER_MSPCONFIGPATH=~/HLF/organizations/peerOrganizations/alpha.olympus.pt/admins/admin.alpha.olympus.pt/msp/
export CORE_PEER_TLS_ROOTCERT_FILE=~/HLF/organizations/peerOrganizations/alpha.olympus.pt/msp/tlscacerts/ca-alpha-olympus-pt-7054.pem
i=$ASSET_INIT
while [ $i -le $ASSET_END ]
do
  ./peer chaincode invoke -o atlas.omega.olympus.pt:7050 --tls --cafile ../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem -C main-channel -n occv3 -c '{"Args":["DeleteAsset","'$((i))'"]}'
i=$((i +1))
done
echo $time

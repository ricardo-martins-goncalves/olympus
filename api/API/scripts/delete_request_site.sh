#!/bin/bash
SECONDS=0
read -p "Range(init): " ASSET_INIT
read -p "Range(end): " ASSET_END
URL=http://zeus.alpha.olympus.pt:8000/controller/delete/
COOKIES=cookies.txt
CURL_BIN="curl -s -c $COOKIES -b $COOKIES -e $URL"


i=$ASSET_INIT
while [ $i -le $ASSET_END ]
do
  $CURL_BIN $URL > /dev/null
  DJANGO_TOKEN="csrfmiddlewaretoken=$(grep csrftoken $COOKIES | sed 's/^.*csrftoken\s*//')"
  #      -d "$DJANGO_TOKEN&user_id=$i&controller_id=1&file=@/home/zeus/API/scripts/data_controller_processor/admins_private_keys/controller_1.pem" \
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
echo $SECONDS
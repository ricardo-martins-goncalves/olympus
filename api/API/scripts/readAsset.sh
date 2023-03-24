#!/bin/bash
read -p "Asset ID: " ASSET_ID
URL=http://zeus.alpha.olympus.pt:8000/read/
COOKIES=cookies.txt
CURL_BIN="curl -s -c $COOKIES -b $COOKIES -e $URL"

$CURL_BIN $URL > /dev/null
DJANGO_TOKEN="csrfmiddlewaretoken=$(grep csrftoken $COOKIES | sed 's/^.*csrftoken\s*//')"
$CURL_BIN \
    -d "$DJANGO_TOKEN&assetid=$ASSET_ID" \
    -X POST $URL
rm $COOKIES

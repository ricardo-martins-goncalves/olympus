#!/bin/bash
URL=http://zeus.alpha.olympus.pt:8000/user/create/
COOKIES=cookies.txt
CURL_BIN="curl -s -c $COOKIES -b $COOKIES -e $URL"

read -p "Start at: " i
read -p "File Name: " file
SECONDS=0
while read -r line; do

  ID=$i
  NAME="$(echo $line | cut -d';' -f1)"
  EMAIL="$(echo $line | cut -d';' -f2)"
  PHONE="$(echo $line | cut -d';' -f3)"
  BIRTHDAY="$(echo $line | cut -d';' -f4)"
  ADDRESS="$(echo $line | cut -d';' -f5)"
  CONSENT="on"


  $CURL_BIN $URL > /dev/null
  DJANGO_TOKEN="csrfmiddlewaretoken=$(grep csrftoken $COOKIES | sed 's/^.*csrftoken\s*//')"

  $CURL_BIN \
      -d "$DJANGO_TOKEN&id=$ID&name=$NAME&email=$EMAIL&phone=$PHONE&birthday=$BIRTHDAY&address=$ADDRESS&consent=$CONSENT" \
      -X POST $URL
  i=$((i+1))

done < $file
echo ""
echo $SECONDS
rm $COOKIES

#!/bin/bash
lines=$(ipfs-cluster-ctl pin ls | cut -b 1-47)


for line in $lines; do
  ipfs-cluster-ctl pin rm $line
done
ipfs-cluster-ctl ipfs gc

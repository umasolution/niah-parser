#!/bin/bash

rm -rf /tmp/niahfeed_latest.tar.gz
rm -rf /tmp/niahfeed_latest.tar
date_now=$(date "+%F-%H-%M-%S")
cp application.config /var/DB/feeds/application/
tar -cvf /tmp/niahfeed_$date_now.tar /var/DB/CVEs /var/DB/feeds
gzip /tmp/niahfeed_$date_now.tar
tar -cvf /tmp/niahfeed_latest.tar /var/DB/CVEs /var/DB/feeds
gzip /tmp/niahfeed_latest.tar

#!/bin/bash

date_now=$(date "+%F-%H-%M-%S")
cp application.config /var/DB/feeds/application/
tar -cvf /tmp/niahfeed_$date_now.tar /var/DB/CVEs /var/DB/feeds
gzip /tmp/niahfeed_$date_now.tar
tar -cvf /tmp/latest.tar /var/DB/CVEs /var/DB/feeds
gzip /tmp/latest.tar

# Update the user/group if your Nginx worker runs as something else.
/var/log/nginx/packs.cordum.io.access.json {
  daily
  rotate 14
  compress
  delaycompress
  missingok
  notifempty
  create 0640 www-data adm
  sharedscripts
  postrotate
    [ -s /run/nginx.pid ] && kill -USR1 `cat /run/nginx.pid`
  endscript
}

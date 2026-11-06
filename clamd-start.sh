cp /var/lib/clamav/* /db/
grep -v -E "^(LogFile|User|Foreground|DatabaseDirectory)" /etc/clamav/clamd.conf > /tmp/clamd.conf
cat >> /tmp/clamd.conf <<EOF
DatabaseDirectory /db
MaxFileSize 1600M
StreamMaxLength 1600M
MaxScanSize 4000M
AlertExceedsMax yes
Foreground yes
EOF
grep -v -E "^(UpdateLogFile|DatabaseOwner|DatabaseDirectory|NotifyClamd|Foreground)" /etc/clamav/freshclam.conf > /tmp/freshclam.conf
echo "DatabaseDirectory /db" >> /tmp/freshclam.conf
echo "NotifyClamd /tmp/clamd.conf" >> /tmp/freshclam.conf
freshclam --daemon --foreground --stdout --checks=1 --config-file=/tmp/freshclam.conf &
exec clamd --config-file=/tmp/clamd.conf

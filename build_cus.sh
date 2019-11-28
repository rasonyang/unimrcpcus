cd  platforms/unimrcp-clientcus
make clean
make
if [ -f /unimrcp/bin/unimrcpclientcus ];then
rm /unimrcp/bin/unimrcpclientcus
fi
sleep 1
cp ./unimrcpclientcus /unimrcp/bin

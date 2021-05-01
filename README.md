# remLocLister
Local File Inclusion &amp; Log Poisoning Enumeration Tool.

![alt text](https://i.imgur.com/E3Q3P2M.png)

Compiled Version for Linux.

*__Example Usage:__*\

#Identify LFI (extensive search) on a Linux OS: \
$ ./remlocLister -u http://url/?page= -i 2 -os "linux" -c "Cookies" \

#Identify potential vulnerable parameter for LFI: \
$ ./remlocLister -u http://url/ -os "linux" -c "Cookies" -p \

#Identify potential log files: \
$ ./remlocLister -u http://url/?page= -os "linux" -c "Cookies" -log \

#Identify LFI adding NullByte bypass: \
$ ./remlocLister -u http://url/?page= -i 1 -os "linux" -c "Cookies" -n \

#Identify LFI using a different User-Agent Header: \
$ ./remlocLister -u http://url/?page= -i 1 -os "linux" -c "Cookies" -uA "User-Agent" \

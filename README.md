# remLocLister
Local File Inclusion &amp; Log Poisoning Enumeration Tool.

![alt text](https://i.imgur.com/E3Q3P2M.png)

Compiled Version for Linux.

# Example Usage:

*__Identify LFI (extensive search) on a Linux OS:__* 
$ ./remlocLister -u http://url/?page= -i 2 -os "linux" -c "Cookies" 

*__Identify potential vulnerable parameter for LFI:__* 
$ ./remlocLister -u http://url/ -os "linux" -c "Cookies" -p 

*__Identify potential log files:__* 
$ ./remlocLister -u http://url/?page= -os "linux" -c "Cookies" -log 

*__Identify LFI adding NullByte bypass:__* 
$ ./remlocLister -u http://url/?page= -i 1 -os "linux" -c "Cookies" -n 

*__Identify LFI using a different User-Agent Header:__* 
$ ./remlocLister -u http://url/?page= -i 1 -os "linux" -c "Cookies" -uA "User-Agent" 

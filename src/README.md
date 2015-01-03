sudo apt-get install libnfnetlink-dev libnetfilter-queue-dev

gcc main.c -o LAF -lnfnetlink -lnetfilter_queue

sudo iptables -A OUTPUT -p all -d <dest ip> -j NFQUEUE --queue-num 0

sudo iptables -A INPUT -s 178.17.41.118/32 -j NFQUEUE --queue-num 0

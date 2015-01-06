Install the required dependencies.

	sudo apt-get install libnfnetlink-dev libnetfilter-queue-dev

Compile with make or gcc:

	gcc main.c procs.c -o LAF -lnfnetlink -lnetfilter_queue

Create an iptables rule:

	sudo iptables -A OUTPUT -p all -j NFQUEUE --queue-num 0

Add entries to the whitelist.txt file as follows:

``<destination_ip> <port>``

``<destination_ip> <port>``

`*` can be used for either as an allow all.

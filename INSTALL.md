Install the required dependencies.

	sudo apt-get install libnfnetlink-dev libnetfilter-queue-dev

Compile with make:

	make

Run [clang](http://clang-analyzer.llvm.org/scan-build.html) static analyser: 

        scan-build  make

Create an iptables rule:

	sudo iptables -A OUTPUT -p all -j NFQUEUE --queue-num 0

Add entries to the whitelist.txt file as follows:

``<destination_ip> <port>``

``<destination_ip> <port>``

`*` can be used for either as an allow all.

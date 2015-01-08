LAF
===

Linux Application Firewall (LAF) is an application firewall for Linux. It allows users full control over which applications are allowed to communicate over the network.

# Alternative to LAF
- [Douaneapp](http://douaneapp.com/) (Kernel Module)
- [Lavender Firewall](http://sourceforge.net/projects/lavenderfw) (Proc Method)
- [Linux Application Firewall](https://github.com/sha0coder/Linux-Application-Firewall) - Development 1 month. (Kernel Module)

## Abandoned Projects

- P [Leopard Flower](http://sourceforge.net/projects/leopardflower/) (Proc Method)
  - [active](https://github.com/andreizilla/leopard-flower-firewall) Fork of Leopard, 14 days activity.
  - [Overwatch](https://github.com/ethanwilloner/Overwatch) Fork of Leopard, Stalled 6 months.
- K [TuxGaurdian](http://tuxguardian.sourceforge.net/) (Kernel Module)
- K [Program Guard](http://pgrd.sourceforge.net/) (Kernel Module)
- [FireFlier](http://fireflier.sourceforge.net/index.html)
- P [afirewall](https://github.com/jkaessens/afirewall) - Development, Stalled 2 years. (Proc Method)

## Related/Interesting Things
- AppArmor - [Specific Networking Option](http://wiki.apparmor.net/index.php/AppArmor_Core_Policy_Reference#Network_rules)
- SE Linux
- [RSBAC](http://www.rsbac.org/documentation/administration_examples/network_access_control?s=nettemp) provides a network template  
- iptables with group matching [ArchForum](https://bbs.archlinux.org/viewtopic.php?pid=1265910#p1265910)
- [DisableNetwork](http://cr.yp.to/unix/disablenetwork.html) document listing possibilities.
- [Vuurmuur Firewall](http://www.vuurmuur.org/trac/)
- P [alcanfw](https://github.com/gamelinux/alcanfw) - Perl script.
- [Maillist Talk about Hone and snet](http://marc.info/?t=140685618600001&r=1&w=2)
  - [snet](https://lkml.org/lkml/2011/5/5/132) linux security module.
  - [HoneProject](https://github.com/HoneProject/Linux-Sensor) Monitoring connections and mapping to PID.
- [Tomoyo](http://tomoyo.sourceforge.jp/2.5/policy-specification/domain-policy-syntax.html.en#network_inet) inet options.
- [caitsith](http://caitsith.sourceforge.jp/) Access restriction module.
- [libseccomp](http://sourceforge.net/projects/libseccomp/) Syscall filtering lib.
- [kernsec](http://kernsec.org/wiki/index.php/Projects)

# Requirements

LAF requires libnetfilter-queue, it's dependency libnfnetlink and a kernel 2.6.14 or later.

	sudo apt-get install libnfnetlink-dev libnetfilter-queue-dev

# Help Needed

If you are a C or a Python developer you can help us improve LAF. Feel free to take a look at the bug tracker for some tasks to do.

# License

LAF is licensed under GPLv3 license. See [LICENSE](src/LICENSE) for more information.
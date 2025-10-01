# packet-sniffer
Simple packet sniffer made with Scapy

This project was made to understand packet manipulation.
It was one of my first project in my first year of BUT R&T.

It's quite simple but still good to learn about unencrypted protocol and why they should not be used anymore.

The following protocol are manipulated :
- FTP
- HTTP
- Telnet
- ICMP
- ARP

## Requirement

In your favorite python venv, install scapy :

```sh
pip install scapy
```

On arch linux, the python-scapy package need to be installed :
```sh
sudo pacman -S python-scapy
```

## Static

In the [static directory](./static), you will find program made to be used with network samples (pcapng files).

## Exploit

It's more fun to manipulate live packets so the [exploit directory](./exploit) contain that kind of programs.

# EtherChat
Experimental chat program based on ethernet frames.

The program uses [gopacket](https://github.com/gopacket/gopacket) to generate frames.


## How to build

```
go build .
```

## How to use

```
etherchat -i <interface>
```

Where `<interface>` is the network interface to use. For example
```
etherchat -i eth0
```

## How it works
- Etherchat will emit broadcast frames to all neighbors
- Each message has a prefix to distinguish from other traffic
- Frames that are non-chat messages are ignored
- Frames from self are ignored
- Chat messages are displayed prefixed with the source MAC that sent them
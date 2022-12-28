<h1 align="center"> HysteriaGen

![version]
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Telegram][telegram-shield]][telegram-url]

</h1>

HysteriaGen helps you to deploy your Hysteria VPN with docker.

> Hysteria is a feature-packed proxy & relay tool optimized for lossy, unstable connections (e.g. satellite networks, congested public Wi-Fi, connecting to foreign servers from China) powered by a customized protocol based on QUIC.

## **How it Works ?**

`HysteriaGen` uses docker-compose to pull hysteria docker image and running it with created configuration file

After deploying it gave you client configuration & URL and QRCode to use that with your device

## **Requirements**

For Running `HysteriaGen` you only need to have python3 on you server

`Docker` will automatically installed of it's not exist in your server

## Usage

**Running Program :**

```bash
curl https://raw.githubusercontent.com/SonyaCore/HysteriaGen/main/hysteria.py -o /tmp/hysteria.py && python3 /tmp/hysteria.py
```

```
   _   _           _            _       _____
  | | | |         | |          (_)     |  __ \
  | |_| |_   _ ___| |_ ___ _ __ _  __ _| |  \/ ___ _ __
  |  _  | | | / __| __/ _ \ '__| |/ _` | | __ / _ \ '_ \
  | | | | |_| \__ \ ||  __/ |  | | (_| | |_\ \  __/ | | |
  \_| |_/\__, |___/\__\___|_|  |_|\__,_|\____/\___|_| |_|
          __/ |
         |___/


HysteriaGen
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Server Information :
Distro : Ubuntu
Kernel : Linux 5.15.0-56-generic aarch64
IP : ###
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
==============================================
[1] Deploying Hysteria using docker-compose
[0] Exit the program
==============================================
```

Use option 1 to deploy hysteria on docker

In option [1] you have several choices

> `Self-signed` certificate for using hysteria without a domain

> `Custom certificate path` for using a sigend certificate and a valid domain name

### Transport protocols

There are several protcols you can choice from

1. UDP
2. Wechat-Video
3. FakeTcp

`UDP` protcol which uses port hopping , The server can then listen on port 5666, while the client connects with example.com:20000-50000.

> Users in China often report that their ISPs block/restrict persistent UDP connections to a single port. Port hopping should invalidate this kind of mechanism.

`Wechat-video` obfuscation feature ( highly recommended in `Iran` )

`faketcp` mode that allows servers and clients to communicate using a protocol that looks like TCP but does not actually go through the system TCP stack. This tricks whatever middleboxes into thinking it’s actually TCP traffic, rendering UDP-specific restrictions useless. (only works on linux and require root privileges)

After specifying the protocol you have to set an authentication password for a password which will prompt you, pressing enter will generate a 6-character random password

## First time use ?

Coming Soon

## Donation

If this Project helped you, you can also help me by donation

### ![tron-button] &nbsp; TTTo7aasobgqH5pKouCJfmPYn2KLed2RA3

### ![bitcoin-button] &nbsp; bc1qgdav05s04qx99mdveuvdt76jauttcwdq687pc8

### ![ethereum-button] &nbsp; 0xD17dF52790f5D6Bf0b29151c7ABC4FFC4056f937

### ![tether-button] &nbsp; 0xD17dF52790f5D6Bf0b29151c7ABC4FFC4056f937

## License

Licensed under the [GPL-3][license] license.

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[tron-button]: https://img.shields.io/badge/TRX-Tron-ff69b4
[tether-button]: https://img.shields.io/badge/ERC20-Tether-purple
[bitcoin-button]: https://img.shields.io/badge/BTC-Bitcoin-orange
[ethereum-button]: https://img.shields.io/badge/ETH-Ethereum-blue
[contributors-shield]: https://img.shields.io/github/contributors/SonyaCore/HysteriaGen?style=flat
[contributors-url]: https://github.com/SonyaCore/HysteriaGen/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/SonyaCore/HysteriaGen?style=flat
[forks-url]: https://github.com/SonyaCore/HysteriaGen/network/members
[stars-shield]: https://img.shields.io/github/stars/SonyaCore/HysteriaGen?style=flat
[stars-url]: https://github.com/SonyaCore/HysteriaGen/stargazers
[issues-shield]: https://img.shields.io/github/issues/SonyaCore/HysteriaGen?style=flat
[issues-url]: https://github.com/SonyaCore/HysteriaGen/issues
[telegram-shield]: https://img.shields.io/badge/Telegram-blue.svg?style=flat&logo=telegram
[telegram-url]: https://t.me/ReiNotes
[license]: LICENSE
[version]: https://img.shields.io/badge/Version-0.3.4-blue

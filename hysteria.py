#!/usr/bin/env python3

# Hysteria Config Generator
# ------------------------------------------
#   Author    : SonyaCore
# 	Github    : https://github.com/SonyaCore
#   Licence   : https://www.gnu.org/licenses/gpl-3.0.en.html

import os
import sys
import subprocess
import socket
import time
import base64
import json
import random
import csv
import hashlib


from urllib.request import urlopen, Request
from urllib.error import HTTPError , URLError

# Name
NAME = "HysteriaGen"
VERSION = "0.1.0"

# Docker Compose Version
DOCKERCOMPOSEVERSION = "2.14.2"
# Docker Compose FILE
DOCKERCOMPOSE = "docker-compose.yml"

SELFSIGEND_CERT = "cert.crt"
SELFSIGEND_KEY = "private.key"

class Color:
    """
    stdout color
    """
    Green = "\u001b[32m"
    Red = "\u001b[31m"
    Yellow = "\u001b[33m"
    Blue = "\u001b[34m"
    Reset = "\u001b[0m"

def get_distro() -> str:
    """
    return distro name based on os-release info with csv module
    """
    RELEASE_INFO = {}
    try :
        with open("/etc/os-release") as f:
            reader = csv.reader(f, delimiter="=")
            for row in reader:
                if row:
                    RELEASE_INFO[row[0]] = row[1]

        return "{}".format(RELEASE_INFO["NAME"])
    except FileNotFoundError :
        sys.exit('OS not detected make sure to use a linux based os')

def install_dependency():
    os = get_distro()
    packages = "lsof curl iptables-persistent"
    if os in ("Ubuntu","Debian GNU/Linux"):
        subprocess.run('apt install -y {}'.format(packages))
    elif os in ("CentOS Linux","Fedora"):
        subprocess.run('yum -y {}'.format(packages))

def kernel_check() -> str:
    os_version = subprocess.run('uname -s -r -p',
    shell=True, stdout=subprocess.PIPE).stdout\
    .decode().strip()
    
    return os_version

# Return IP
def IP():
    """
    return actual IP of the server.
    if there are multiple interfaces with private IP the public IP will be used for the config
    """
    try:
        url = "https://api64.ipify.org"
        httprequest = Request(url)

        with urlopen(httprequest) as response:
            data = response.read().decode()
            return data
    except HTTPError:
        print(
            Color.Red
            + 'failed to send request to {} please check your connection'.format(url)
            + Color.Reset
        )
        sys.exit(1)

def port_is_use(port):
    """
    check if port is used for a given port
    """
    state = False
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stream.settimeout(2)
    try:
        if stream.connect_ex(("127.0.0.1", int(port))) == 0:
            state = True
        else:
            state = False
    finally:
        stream.close()
    return state

def qrcode(data, width=76, height=76) -> str:
    qrcode = Request(
        "https://qrcode.show/{}".format(data),
        headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/octet-stream",
            "X-QR-Version-Type": "micro",
            "X-QR-Quiet-Zone": "true",
            "X-QR-Min-Width": width,
            "X-QR-Min-Height": height,
        },
    )

    with urlopen(qrcode) as response:
        return response.read().decode()

def run_docker():
    """
    Start xray docker-compose.
    at first, it will check if docker exists and then check if docker-compose exists
    if docker is not in the path it will install docker with the official script.
    then it checks the docker-compose path if the condition is True docker-compose.yml will be used for running xray.
    """
    try:
        # Check if docker exist
        if os.path.exists("/usr/bin/docker") or os.path.exists("/usr/local/bin/docker"):
            pass
        else:
            # Install docker if docker are not installed
            try:
                print(yellow + "Docker Not Found.\nInstalling Docker ...")
                subprocess.run(
                    "curl https://get.docker.com | sh", shell=True, check=True
                )
            except subprocess.CalledProcessError:
                sys.exit(error + "Download Failed !" + reset)

        # Check if Docker Service are Enabled
        systemctl = subprocess.call(["systemctl", "is-active", "--quiet", "docker"])
        if systemctl == 0:
            pass
        else:
            subprocess.call(["systemctl", "enable", "--now", "--quiet", "docker"])

        time.sleep(2)

        # Check if docker-compose exist
        if os.path.exists("/usr/bin/docker-compose") or os.path.exists(
            "/usr/local/bin/docker-compose"
        ):
            subprocess.run(
                f"docker-compose -f {DOCKERCOMPOSE} up -d", shell=True, check=True
            )
            reset_docker_compose()
        else:
            print(
                Color.Yellow
                + f"docker-compose Not Found.\nInstalling docker-compose v{DOCKERCOMPOSEVERSION} ..."
            )
            subprocess.run(
                f"curl -SL https://github.com/docker/compose/releases/download/v{DOCKERCOMPOSEVERSION}/docker-compose-linux-x86_64 \
        -o /usr/local/bin/docker-compose",
                shell=True,
                check=True,
            )
            subprocess.run(
                "chmod +x /usr/local/bin/docker-compose", shell=True, check=True
            )
            subprocess.run(
                "ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose",
                shell=True,
                check=True,
            )

            subprocess.run(
                f"docker-compose -f {DOCKERCOMPOSE} up -d", shell=True, check=True
            )
    except subprocess.CalledProcessError as e:
        sys.exit(Color.Red + str(e) + Color.Reset)
    except PermissionError:
        sys.exit(Color.Red + "ًroot privileges required" + Color.Reset)


def reset_docker_compose():
    subprocess.run(f"docker-compose restart", shell=True, check=True)


def create_key():
    """
    create self signed key with openssl
    """
    cn = "www.bing.com"
    print(Color.Green)
    subprocess.run(
    "openssl ecparam -genkey -name prime256v1 -out {}".format(SELFSIGEND_KEY),
    shell=True,check=True)
    subprocess.run(
    "openssl req -new -x509 -days 36500 -key {} -out {} -subj '/CN={}'"
    .format(SELFSIGEND_KEY,SELFSIGEND_CERT,cn),
    shell=True,check=True)
    print(Color.Reset)
    print(Color.Blue + "Confirmed certificate mode: www.bing.com self-signed certificate\n" + Color.Reset)


def certificate():

    user_input = ''

    input_message = "Select an option:\n"

    options = ['www.bing.com self-signed certificate',
    'Acme one-click certificate application script (supports regular port 80 mode and dns api mode)',
    'Custom certificate path\n']

    for index, item in enumerate(options):
        input_message += f'{index+1}) {item}\n'

    input_message += 'Your choice: '

    while user_input not in map(str, range(1, len(options) + 1)):
        user_input = input(input_message)

    print('Selected: ' + options[int(user_input) - 1])

    select = options[int(user_input) - 1]
    if select == options[0] :
        create_key()

    elif select == options[1]:
        subprocess.run("curl https://get.acme.sh | sh" , shell=True , check= True)

    elif select == options[2] :
        cert_path = input("Enter the path of the public key file crt (/etc/key/cert.crt) : ")
        if os.path.exists(cert_path):
            print(Color.Blue + "CRT FILE : " + cert_path + Color.Reset)
        else:
            print(Color.Red + "Invalid Path" + Color.Reset)
            return certificate()
        key_path = input("Enter the path of the key file (/etc/key/private.key) : ")
        if os.path.exists(key_path):
            print(Color.Blue + "Key FILE : " + key_path + Color.Reset)
        else:
            print(Color.Red + "Invalid Path" + Color.Reset)
            return certificate()
        
        cert = cert_path
        private = key_path

        domain_name = input("Please enter the resolved domain name:")
        print(Color.Blue + "Resolved domain name: {} ".format(domain_name) + Color.Reset)
    
def protocol():
    global hysteria_protocol
    user_input = ''

    input_message = (Color.Green + "Select transport protocol for hysteria:\n" + Color.Reset)
    
    options = [
    "UDP (support range port hopping function, press Enter to default)",
    "Wechat-Video",
    "FakeTcp (only supports linux or Android client and requires root privileges)"]

    for index, item in enumerate(options):
        input_message += f'{index+1}) {item}\n'

    while user_input not in map(str, range(1, len(options) + 1)):
        user_input = input(input_message)

    select = options[int(user_input) - 1]

    if select == options[0] :
        hysteria_protocol = "udp"
    elif select == options[1] :
        hysteria_protocol = "wechat-video"
    elif select == options[0] :
        hysteria_protocol = "faketcp"
    print(Color.Blue + "Transport Protocol : {}".format(hysteria_protocol) + Color.Reset)


def hysteria_template():
    """
    Create ShadowSocks docker-compose file for shadowsocks-libev.
    in this docker-compose shadowsocks-libev is being used for running shadowsocks in the container.
    https://hub.docker.com/r/shadowsocks/shadowsocks-libev
    """

    data = """version: '3.9'
services:
  hysteria:
    image: tobyxdd/hysteria
    container_name: hysteria
    restart: always
    network_mode: "host"
    volumes:
      - ./hysteria.json:/etc/hysteria.json
    command: ["server", "--config", "/etc/hysteria.json"]"""

    print(Color.Blue + "Created Hysteria {} configuration".format(DOCKERCOMPOSE) + Color.Reset)
    with open(DOCKERCOMPOSE, "w") as txt:
        txt.write(data)
        txt.close()
        

def generate_password():
    # Get current timestamp in nanoseconds
    timestamp = time.time_ns()

    # Calculate the MD5 hash of the timestamp
    hash_object = hashlib.md5(str(timestamp).encode())

    return hash_object.hexdigest()[:6]

def password():
    password_input = input("Set the hysteria authentication password, Press enter for random password : ")
    if password_input == "":
        password_input = generate_password()
    elif len(password_input) < 6 :
        print(Color.Yellow + "\nPassword must be more than 6 characters! Please re-enter" + Color.Reset)
        return password()

    print(Color.Blue + "Authentication Password confirmed: {}\n".format(password_input) + Color.Reset)

def hysteria_config():
    v4 = IP()
    config_name = 'hysteria.json'
    
    data = """
    {
    "listen": ":{port}",
    "protocol": "${hysteria_protocol}",
    "resolve_preference": "${rpip}",
    "auth": {
    "mode": "password",
    "config": {
    "password": "${pswd}"
    }
    },
    "alpn": "h3",
    "cert": "${certificatec}",
    "key": "${certificatep}"
    }"""

    with open(config_name,'w') as config :
        config.write(data)
        config.close()

# print(get_distro())
# kernel_check()
# print(IP())
# certificate()
protocol()
hysteria_template()
password()
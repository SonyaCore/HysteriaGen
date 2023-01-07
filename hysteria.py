#!/usr/bin/env python3

# Hysteria Config Generator
# ------------------------------------------
#   Author    : SonyaCore
# 	Github    : https://github.com/SonyaCore
#   License   : https://www.gnu.org/licenses/gpl-3.0.en.html

import os
import sys
import subprocess
import socket
import time
import json
import random
import csv
import hashlib
import signal
import string
import re

from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

# Name
NAME = "HysteriaGen"
VERSION = "0.4.0"

# Docker Compose Version
DOCKERCOMPOSEVERSION = "2.14.2"
# Docker Compose FILE
DOCKERCOMPOSE = "docker-compose.yml"

SELFSIGEND_CERT = "cert.crt"
SELFSIGEND_KEY = "private.key"

MIN_PORT = 1
MAX_PORT = 65535


## Global Config
sys.tracebacklimit = 0

#####################################
class Color:
    """
    stdout color
    """

    Green = "\u001b[32m"
    Red = "\u001b[31m"
    Yellow = "\u001b[33m"
    Blue = "\u001b[34m"
    Cyan = "\u001b[36m"
    Reset = "\u001b[0m"


#####################################


#####################################
class Hysteria:
    """
    Hysteria Configuration Instance
    """

    ## Domain
    DOMAIN_NAME: str = None
    INSECURE: str = None
    CONFIG: bool = None
    ## Certificate
    CERT: str = None
    PRIVATE: str = None
    ## Server Configuration
    PORT: int = None
    PROTOCOL: str = None
    PASSWORD: str = None
    AUTH_TYPE: str = None


#####################################


def signal_handler(sig, frame):
    print(Color.Red + "\nKeyboardInterrupt!")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def banner(t=0.0010):
    banner = """
{cyan}   _   _           _            _       _____            {reset}
{cyan}  | | | |         | |          (_)     |  __ \           {reset}
{blue}  | |_| |_   _ ___| |_ ___ _ __ _  __ _| |  \/ ___ _ __  {reset}
{blue}  |  _  | | | / __| __/ _ \ '__| |/ _` | | __ / _ \ '_ \ {reset}
{red}  | | | | |_| \__ \ ||  __/ |  | | (_| | |_\ \  __/ | | |{reset}
{red}  \_| |_/\__, |___/\__\___|_|  |_|\__,_|\____/\___|_| |_|{reset}
{yellow}          __/ |                                          {reset}
{yellow}         |___/                                           {reset}

    """.format(
        green=Color.Green,
        reset=Color.Reset,
        blue=Color.Blue,
        red=Color.Red,
        yellow=Color.Yellow,
        cyan=Color.Cyan,
    )
    for char in banner:
        sys.stdout.write(char)
        time.sleep(t)
    sys.stdout.write("\n")


def get_distro() -> str:
    """
    return distro name based on os-release info with csv module
    """
    RELEASE_INFO = {}
    try:
        with open("/etc/os-release") as f:
            reader = csv.reader(f, delimiter="=")
            for row in reader:
                if row:
                    RELEASE_INFO[row[0]] = row[1]

        return "{}".format(RELEASE_INFO["NAME"])
    except FileNotFoundError:
        sys.exit("OS not detected make sure to use a linux based OS")

def save_config(config : str, data : str) -> None:
    with open(config, "w") as file:
        json.dump(data, file, indent=2)

        Docker().reset_docker_compose()

def read_config(config: str) -> None:
    with open(config, "r") as configfile:
        return json.loads(configfile.read())

def load_config():
    global config
    try:
        config = sys.argv[1]
    except IndexError:
        config = "hysteria.json"
    try:
        with open(config, "r") as configfile:
            configfile.read()
            print(Color.Green + "Config : " + Color.Reset + config)
            Hysteria.CONFIG = True
    except FileNotFoundError:
        print(Color.Green + "Config : " + Color.Reset + 'NOT EXIST')
        Hysteria.CONFIG = False

def read_port(config):
    data = read_config(config)
    port = data["listen"][1:]
    return port
    

def read_password(config):
    data = read_config(config)

    try :
        if data["obfs"]:
            password = data["obfs"]
    except KeyError:
        pass
    try :
        if data["auth"]:
            password = data["auth"]["config"]["password"]

    except KeyError:
        pass

    try :
        return password

    except UnboundLocalError:
        raise PasswordNotFound(Color.Red + "Invalid config , Password not found !" + Color.Reset)



def validate_port(port):
    if port < MIN_PORT or port > MAX_PORT:
        print("Port number must be between %d and %d." % (MIN_PORT, MAX_PORT))
        raise TypeError
    else:
        pass

def install_dependency():
    os = get_distro()
    packages = "lsof curl iptables-persistent"
    if os in ("Ubuntu", "Debian GNU/Linux"):
        subprocess.run("apt install -y {}".format(packages), shell=True, check=True)
    elif os in ("CentOS Linux", "Fedora"):
        subprocess.run("yum -y {}".format(packages), shell=True, check=True)


def kernel_check() -> str:
    os_version = (
        subprocess.run("uname -s -r -p", shell=True, stdout=subprocess.PIPE)
        .stdout.decode()
        .strip()
    )

    return os_version


# Return IP
def IP():
    """
    return actual IP of the server.
    if there are multiple interfaces with private IP the public IP will be used for the config
    """
    try:
        url = "http://ip-api.com/json/?fields=query"
        httprequest = Request(url, headers={"Accept": "application/json"})

        with urlopen(httprequest) as response:
            data = json.loads(response.read().decode())
            return data["query"]
    except HTTPError:
        print(
            Color.Red
            + f'failed to send request to {url.split("/json")[0]} please check your connection'
            + Color.Reset
        )
        sys.exit(1)


ServerIP = IP()


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


def validate_domain(domain):
    regex = r"^(((?!\-))(xn\-\-)?[a-z0-9\-_]{0,61}[a-z0-9]{1,1}\.)*(xn\-\-)?([a-z0-9\-]{1,61}|[a-z0-9\-]{1,30})\.[a-z]{2,}$"
    if re.fullmatch(regex, domain):
        pass
    else:
        print("Please enter a valid domain name")
        raise TypeError


class ImageNotFound(Exception):
    pass
class PasswordNotFound(Exception):
    pass

def change_hysteria_port():
    try :
        port = int(input('Enter a PORT : '))
    except ValueError:
        print(Color.Red + "PORT must be a integer value" + Color.Reset)
        return
    try:
        validate_port(port)
    except TypeError:
        return 

    data = read_config(config)
    configport = read_port(config)
    data["listen"] = port

    if port_is_use(port):
        print("PORT {} is being used. try another".format(Color.Green + str(port) + Color.Reset))
        return 
    else:
        confirm = input("Change PORT {}{}{} to {}{}{} ? [y/n] ".format(
            Color.Yellow , configport , Color.Reset , Color.Green, port , Color.Reset))
        if confirm.lower() in ["y", "yes"]:

            data["listen"] = ":"+ str(port)
            save_config(config, data)

            print("Hysteria PORT changed to {}{}".format(Color.Yellow , port))
        else:
            pass

def change_hysteria_password():
    password = str(input('Enter a Password or press enter for random : '))
    if len(password) == 0 :
        password = random_password()

    data = read_config(config)
    configpass = read_password(config)
    try :
        if data["obfs"]:
            data["obfs"] = password
    except KeyError:
        pass

    try :
        if data["auth"]:
            data["auth"]["config"]["password"] = password
    except KeyError:
        pass

    confirm = input("Change PASSWORD {}{}{} to {}{}{} ? [y/n] ".format(
        Color.Yellow , configpass , Color.Reset , Color.Green, password , Color.Reset))
    if confirm.lower() in ["y", "yes"]:
        save_config(config, data)

        print("Hysteria PASSWORD changed to {}{}".format(Color.Yellow , password))
    else:
        pass

class Docker:
    """
    main docker module with subprocess.
    this module check for docker status & docker binary file in /usr/bin/docker
    if docker is not in the path it will install docker with the official script.
    then it checks the docker-compose path if the condition is True docker-compose.yml will be used for running hysteria.
    """

    def __init__(self) -> None:
        self.dockercompose = DOCKERCOMPOSE
        self.dockercompose_version = DOCKERCOMPOSEVERSION

    def check_docker(self):
        """
        check docker installation file
        """
        try:
            if os.path.exists("/usr/bin/docker") or os.path.exists(
                "/usr/local/bin/docker"
            ):
                pass
            else:
                # Install docker if docker are not installed
                print(Color.Yellow + "Docker Not Found.\nInstalling Docker ...")
                subprocess.run(
                    "curl https://get.docker.com | sh", shell=True, check=True
                )
        except subprocess.CalledProcessError:
            sys.exit(Color.Red + "Download Failed !" + Color.Reset)

    def docker_service(self):
        """
        Check docker service status
        """
        systemctl = subprocess.call(["systemctl", "is-active", "--quiet", "docker"])
        if systemctl == 0:
            pass
        else:
            subprocess.call(["systemctl", "enable", "--now", "--quiet", "docker"])

    def check_docker_compose(self):
        """
        check docker installation file
        """
        if os.path.exists("/usr/bin/docker-compose") or os.path.exists(
            "/usr/local/bin/docker-compose"
        ):
            self.run_docker_compose()
            self.reset_docker_compose()
        else:
            print(
                Color.Yellow
                + f"docker-compose Not Found.\nInstalling docker-compose v{self.dockercompose_version} ..."
            )
            subprocess.run(
                f"curl -SL https://github.com/docker/compose/releases/download/v{self.dockercompose_version}/docker-compose-linux-x86_64 \
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
            self.run_docker_compose()

    def run_docker_compose(self):
        subprocess.run(
            f"docker-compose -f {self.dockercompose} up -d", shell=True, check=True
        )

    def remove_docker_images(self, name: str):
        lists = self.list_docker_image_names(name)

        for remove in lists:
            subprocess.run(
                ["docker", "kill", remove], stdout=subprocess.PIPE
            ).stdout.decode()
            subprocess.run(
                ["docker", "rm", remove], stdout=subprocess.PIPE
            ).stdout.decode()

    def list_docker_image_names(self, name: str):
        output = subprocess.run(
            ["docker", "ps", "-a"], stdout=subprocess.PIPE
        ).stdout.decode()

        lines = output.split("\n")

        filtered_lines = [line.split(" ")[0] for line in lines if name in line]

        if len(filtered_lines) == 0:
            raise ImageNotFound
        else:
            return filtered_lines

    def reset_docker_compose(self):
        subprocess.run(f"docker-compose restart", shell=True, check=True)


def run_docker() -> None:
    docker = Docker()
    docker.check_docker()
    docker.docker_service()
    docker.check_docker_compose()


def create_key():
    """
    create self signed key with openssl
    """
    cn = "www.bing.com"
    print(Color.Green)
    subprocess.run(
        "openssl ecparam -genkey -name prime256v1 -out {}".format(SELFSIGEND_KEY),
        shell=True,
        check=True,
    )
    subprocess.run(
        "openssl req -new -x509 -days 36500 -key {} -out {} -subj '/CN={}'".format(
            SELFSIGEND_KEY, SELFSIGEND_CERT, cn
        ),
        shell=True,
        check=True,
    )
    print(Color.Reset)
    print(
        Color.Blue
        + "Confirmed certificate mode: www.bing.com self-signed certificate\n"
        + Color.Reset
    )


def certificate():
    user_input = ""

    input_message = "Select an option:\n"

    options = ["www.bing.com self-signed certificate", "Custom certificate path\n"]

    for index, item in enumerate(options):
        input_message += f"{index+1}) {item}\n"

    input_message += "Your choice: "

    while user_input not in map(str, range(1, len(options) + 1)):
        user_input = input(input_message)

    print("Selected: " + options[int(user_input) - 1])

    select = options[int(user_input) - 1]
    if select == options[0]:
        create_key()
        Hysteria.CERT = SELFSIGEND_CERT
        Hysteria.PRIVATE = SELFSIGEND_KEY
        Hysteria.INSECURE = "true"
        Hysteria.DOMAIN_NAME = "www.bing.com"

    elif select == options[1]:
        cert_path = input(
            "Enter the path of the public key file crt (/etc/key/cert.crt) : "
        )

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

        Hysteria.CERT = cert_path
        Hysteria.PRIVATE = key_path

        Hysteria.DOMAIN_NAME = input("Enter the resolved domain name : ")
        try:
            validate_domain(Hysteria.DOMAIN_NAME)
        except TypeError:
            print(Color.Red + "Invalid Domain Name !\n" + Color.Reset)
            return certificate()

        Hysteria.INSECURE = "false"
        print(
            Color.Blue
            + "Resolved domain name: {} ".format(Hysteria.DOMAIN_NAME)
            + Color.Reset
        )


def port_hopping():
    global firstudpport, endudpport

    fudpmsg = "\nAdd a START port for the range (recommended between 10000-65535) : "
    eudpmsg = (
        "\nAdd an END port for the range , should be greater than the starting port) : "
    )

    try:
        firstudpport = int(input(fudpmsg))
        endudpport = int(input(eudpmsg))
    except ValueError:
        print(Color.Red + "PORT must be a integer value" + Color.Reset)
        return port_hopping()

    if firstudpport >= endudpport:
        while firstudpport > endudpport:
            if firstudpport >= endudpport:
                print(
                    Color.Yellow
                    + "\nStarting port is less than ending port. Please re-enter starting/ending ports"
                    + Color.Reset
                )
                return port_hopping()

    subprocess.call(
        [
            "iptables",
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-p",
            "udp",
            "--dport",
            str(firstudpport) + ":" + str(endudpport),
            "-j",
            "DNAT",
            "--to-destination",
            ":" + str(Hysteria.PORT),
        ]
    )
    subprocess.call(
        [
            "ip6tables",
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-p",
            "udp",
            "--dport",
            str(firstudpport) + ":" + str(endudpport),
            "-j",
            "DNAT",
            "--to-destination",
            ":" + str(Hysteria.PORT),
        ]
    )
    # subprocess.call(["netfilter-persistent", "save"])
    print(
        "\nConfirmed range of forwarded ports: "
        + str(firstudpport)
        + " to "
        + str(endudpport)
        + "\n"
    )


def protocol():
    user_input = ""

    input_message = (
        Color.Green + "Select transport protocol for hysteria:\n" + Color.Reset
    )

    options = [
        "UDP (support range port hopping function)",
        "Wechat-Video , recommended",
        "FakeTcp (only supports on linux requires root privileges)",
    ]

    for index, item in enumerate(options):
        input_message += f"{index+1}) {item}\n"

    while user_input not in map(str, range(1, len(options) + 1)):
        user_input = input(input_message)

    select = options[int(user_input) - 1]

    if select == options[0]:
        Hysteria.PROTOCOL = "udp"
        port_hopping()

    elif select == options[1]:
        Hysteria.PROTOCOL = "wechat-video"

    elif select == options[2]:
        Hysteria.PROTOCOL = "faketcp"

    print(
        Color.Blue + "Transport Protocol : {}".format(Hysteria.PROTOCOL) + Color.Reset
    )


def hysteria_template():
    docker_certkey = "- ./{}:/etc/hysteria/{}:ro".format(
        SELFSIGEND_CERT, SELFSIGEND_CERT
    )

    docker_hostkey = "- ./{}:/etc/hysteria/{}:ro".format(SELFSIGEND_KEY, SELFSIGEND_KEY)

    data = """version: '3.9'
services:
  hysteria:
    image: tobyxdd/hysteria
    restart: always
    network_mode: "host"
    volumes:
      - ./hysteria.json:/etc/hysteria.json
      %s
      %s
    command: ["server", "--config", "/etc/hysteria.json"]""" % (
        docker_certkey,
        docker_hostkey,
    )

    print(
        Color.Blue
        + "Created Hysteria {} configuration".format(DOCKERCOMPOSE)
        + Color.Reset
    )
    with open(DOCKERCOMPOSE, "w") as txt:
        txt.write(data)
        txt.close()


def generate_password() -> str:
    # Get current timestamp in nanoseconds
    timestamp = time.time_ns()

    # Calculate the MD5 hash of the timestamp
    hash_object = hashlib.md5(str(timestamp).encode())

    return hash_object.hexdigest()[:6]


def random_password(len: int = 32) -> str:
    "Generate random password"
    randomstring = "".join(random.choices(string.ascii_letters + string.digits, k=len))
    return str(randomstring)


def random_port(min: int = 2000, max: int = MAX_PORT) -> int:
    return random.randint(min, max)


def port():
    try:
        Hysteria.PORT = input(
            "Set hysteria port [1-65535] (Press Enter for a random port between 2000-65535): "
        )
        if len(Hysteria.PORT) == 0:
            Hysteria.PORT = random_port()

        Hysteria.PORT = int(Hysteria.PORT)

        if Hysteria.PORT < MIN_PORT:
            print(Color.Red + "PORT Can't be below 0" + Color.Reset)
            return port()

        if Hysteria.PORT > MAX_PORT:
            print(Color.Red + "PORT can't be more than" + str(MAX_PORT) + Color.Reset)
            return port()

        if port_is_use(Hysteria.PORT):
            print(Color.Red + "PORT is already being used" + Color.Reset)
            return port()

        print(Color.Blue + "Hysteria PORT : " + str(Hysteria.PORT) + Color.Reset)
    except ValueError:
        print(Color.Red + "PORT must be a integer value" + Color.Reset)
        return port()


def password():

    user_input = ""

    input_message = Color.Green + "Select Authentication Type :\n" + Color.Reset

    options = ["OBFS", "STRING"]

    for index, item in enumerate(options):
        input_message += f"{index+1}) {item}\n"

    while user_input not in map(str, range(1, len(options) + 1)):
        user_input = input(input_message)

    select = options[int(user_input) - 1]

    if select == options[0]:
        Hysteria.AUTH_TYPE = "OBFS"
        Hysteria.PASSWORD = random_password()
        print(
            Color.Blue
            + "OBFS password confirmed: {}\n".format(
                Color.Yellow + Hysteria.PASSWORD + Color.Reset
            )
            + Color.Reset
        )

    elif select == options[1]:
        Hysteria.AUTH_TYPE = "STRING"
        Hysteria.PASSWORD = input(
            "Set the hysteria authentication password, Press enter for a random password : "
        )
        if Hysteria.PASSWORD == "":
            Hysteria.PASSWORD = generate_password()
        elif len(Hysteria.PASSWORD) < 6:
            print(
                Color.Yellow
                + "\nPassword must be more than 6 characters! Please re-enter"
                + Color.Reset
            )
            return password()

        print(
            Color.Blue
            + "Authentication password confirmed: {}\n".format(
                Color.Yellow + Hysteria.PASSWORD + Color.Reset
            )
            + Color.Reset
        )


def hysteria_config():

    config_port = Hysteria.PORT
    if Hysteria.PROTOCOL == "udp":
        config_port = "{},{}-{}".format(Hysteria.PORT, firstudpport, endudpport)
    else:
        config_port = Hysteria.PORT

    if Hysteria.AUTH_TYPE == "STRING":
        auth = """
        "auth": {
        "mode": "password",
        "config": {
        "password": "%s"
        }
        }""" % (
            Hysteria.PASSWORD
        )

    elif Hysteria.AUTH_TYPE == "OBFS":
        auth = """ "obfs": "%s" """ % (Hysteria.PASSWORD)
    # IPv4
    ref = 46
    config_name = "hysteria.json"

    data = """
    {
    "listen": ":%s",
    "protocol": "%s",
    "resolve_preference": "%s",
    %s,
    "alpn": "h3",
    "cert": "/etc/hysteria/%s",
    "key": "/etc/hysteria/%s"
    }""" % (
        config_port,
        Hysteria.PROTOCOL,
        ref,
        auth,
        Hysteria.CERT,
        Hysteria.PRIVATE,
    )

    with open(config_name, "w") as config:
        config.write(json.dumps(json.loads(data), indent=2))


def client_config():
    config_name = "client.json"

    if Hysteria.AUTH_TYPE == "STRING":
        auth = """ 
        "auth_str": "%s"
        """ % (
            Hysteria.PASSWORD
        )
    elif Hysteria.AUTH_TYPE == "OBFS":
        auth = """
        "obfs": "%s"
        """ % (
            Hysteria.PASSWORD
        )

    data = """
{
"server": "%s:%s",
"protocol": "%s",
"up_mbps": 20,
"down_mbps": 100,
"alpn": "h3",
"http": {
"listen": "127.0.0.1:10809",
"timeout" : 300,
"disable_udp": false
},
"socks5": {
"listen": "127.0.0.1:10808",
"timeout": 300,
"disable_udp": false
},
%s,
"server_name": "%s",
"insecure": %s,
"retry": 3,
"retry_interval": 3,
"fast_open": true,
"hop_interval": 60
}""" % (
        ServerIP,
        Hysteria.PORT,
        Hysteria.PROTOCOL,
        auth,
        Hysteria.DOMAIN_NAME,
        Hysteria.INSECURE,
    )

    with open(config_name, "w") as clientconfig:
        clientconfig.write(json.dumps(json.loads(data), indent=2))

        print(Color.Blue + "Client Configuration Created !" + Color.Reset)
        print(
            Color.Yellow
            + "Use the below configuration on the hysteria client "
            + Color.Reset
        )

        data = json.dumps(json.loads(data), indent=2)
        for char in data:
            sys.stdout.write(char)
            time.sleep(0.005)
        sys.stdout.write("\n")


def hysteria_url(linkname):
    if Hysteria.AUTH_TYPE == "STRING":
        auth = "auth={}".format(Hysteria.PASSWORD)
    elif Hysteria.AUTH_TYPE == "OBFS":
        auth = "obfs=xplus&obfsParam={}".format(Hysteria.PASSWORD)

    Hysteria.INSECURE = 1 if Hysteria.INSECURE == "true" else 0

    url = "hysteria://{}:{}?protocol={}&{}&peer={}&insecure={}&upmbps=10&downmbps=50&alpn=h3#{}".format(
        ServerIP,
        Hysteria.PORT,
        Hysteria.PROTOCOL,
        auth,
        Hysteria.DOMAIN_NAME,
        Hysteria.INSECURE,
        linkname,
    )

    return url


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


def shell():
    try:
        shellcmd = Color.Green + "# : " + Color.Reset
        option = int(input(shellcmd))
        return option
    except ValueError:
        print(Color.Red + "Invalid Option." + Color.Reset)
        return shell()


def server_information() -> str:
    print(Color.Green + "Server Information : " + Color.Reset)
    print(Color.Green + "Distro : " + Color.Reset + get_distro())
    print(Color.Green + "Kernel : " + Color.Reset + kernel_check())
    print(Color.Green + "IP : " + Color.Reset + ServerIP)
    load_config()

def menu_option() -> str:
    print(Color.Yellow + 'Deployment : ' + Color.Reset)
    print("[1] Deploying Hysteria using docker-compose")
    print("[2] Removing all Hystoria images")
    print(Color.Cyan + "=" * 50 + Color.Reset)
    print(Color.Yellow + 'Configuration : ' + Color.Reset)
    print("[3] Change PORT")
    print("[4] Change PASSWORD")
    print(Color.Cyan + "=" * 50 + Color.Reset)

    print("[0] Exit the program")


def confignotfound():
    print(Color.Red + "Configuration File not found !" + Color.Reset)

def menu():
    banner()
    print(Color.Blue + NAME + " " + VERSION + Color.Reset)
    print("~" * 100)
    server_information()
    print("~" * 100)

    print(Color.Green + "=" * 100 + Color.Reset)
    menu_option()
    print(Color.Green + "=" * 100 + Color.Reset)

    option = shell()
    while option != 0:
        if option == 1:
            print(Color.Green + "Deploying Hysteria " + Color.Reset)
            certificate()
            port()
            firewall()
            protocol()
            password()
            hysteria_config()
            hysteria_template()
            run_docker()
            print(Color.Red + "=" * 100 + Color.Reset)
            client_config()
            print(Color.Yellow + "Use below url for your client : " + Color.Reset)
            print(hysteria_url("hysteria"))
            print(Color.Red + "=" * 100 + Color.Reset)
            print(Color.Yellow + "QRCode : " + Color.Reset)
            print(qrcode(hysteria_url("hysteria")))
            break

        elif option == 2:
            dockerlist = Docker()

            try:
                names = dockerlist.list_docker_image_names("hysteria")
                for name in names:
                    print(name)

                confirm = input(Color.Red + "Delete these images? : " + Color.Reset)

                if confirm.lower() in ["y", "yes"]:
                    dockerlist.remove_docker_images("hysteria")
                    print(Color.Green + "Remove Complete" + Color.Reset)
                else:
                    pass
            except ImageNotFound:
                print(Color.Yellow + "No Hysteria images found ! " + Color.Reset)
                pass

        elif option == 3:
            if Hysteria.CONFIG == True :
                print(Color.Green + "Current PORT : " + Color.Reset + read_port(config))
                change_hysteria_port()
            else :
                confignotfound()
        elif option == 4:
            if Hysteria.CONFIG == True :
                print(Color.Green + "Current PASSWORD : " + Color.Reset + read_password(config))
                change_hysteria_password()
            else :
                confignotfound()

        else:
            print(Color.Red + "Invalid Option." + Color.Reset)

        option = shell()


#####################################


def firewall():
    """
    add configuration port to firewall.
    by default, it checks if the "ufw" or "firewalld" exists and adds the rule to the firewall
    else iptables firewall rule will be added
    """
    try:
        if os.path.exists("/usr/sbin/ufw"):
            service = "ufw"
            subprocess.run(f"ufw allow {Hysteria.PORT}", check=True, shell=True)
        elif os.path.exists("/usr/sbin/firewalld"):
            service = "firewalld"
            subprocess.run(
                f"firewall-cmd --permanent --add-port={Hysteria.PORT}/tcp",
                shell=True,
                check=True,
            )
        else:
            service = "iptables"
            subprocess.run(
                f"iptables -t filter -A INPUT -p tcp --dport {Hysteria.PORT} -j ACCEPT",
                shell=True,
                check=True,
            )
            subprocess.run(
                f"iptables -t filter -A OUTPUT -p tcp --dport {Hysteria.PORT} -j ACCEPT",
                shell=True,
                check=True,
            )
        print(
            Color.Green
            + "Added "
            + str(Hysteria.PORT)
            + " "
            + "to "
            + service
            + Color.Reset
        )
        print("-----------------")
    except subprocess.CalledProcessError as e:
        sys.exit(Color.Reset + str(e) + Color.Reset)


if __name__ == "__main__":
    menu()

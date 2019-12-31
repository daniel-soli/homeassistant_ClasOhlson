#!/usr/bin/python

import codecs
import random
import socket
import threading
import json
import struct
import time
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def gendevice(devtype, host, mac):
    devices = {
        sp2: [0x2711,  # SP2
              0x2719, 0x7919, 0x271a, 0x791a,  # Honeywell SP2
              0x2720,  # SPMini
              0x753e,  # SP3
              0x7D00,  # OEM branded SP3
              0x947a, 0x9479,  # SP3S
              0x2728,  # SPMini2
              0x2733, 0x273e,  # OEM branded SPMini
              0x7530, 0x7546, 0x7918,  # OEM branded SPMini2
              0x7D0D,  # TMall OEM SPMini3
              0x2736  # SPMiniPlus
              ],
        sp4: [0x7579], #SP4 (L-EU(AU/US?))
    }

    # Look for the class associated to devtype in devices
    [device_class] = [dev for dev in devices if devtype in devices[dev]] or [None]
    if device_class is None:
        return device(host=host, mac=mac, devtype=devtype)
    return device_class(host=host, mac=mac, devtype=devtype)


def discover(timeout=None, local_ip_address=None):
    if local_ip_address is None:
        local_ip_address = socket.gethostbyname(socket.gethostname())
    if local_ip_address.startswith('127.'):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 53))  # connecting to a UDP address doesn't send packets
        local_ip_address = s.getsockname()[0]
    address = local_ip_address.split('.')
    cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    cs.bind((local_ip_address, 0))
    port = cs.getsockname()[1]
    starttime = time.time()

    devices = []

    timezone = int(time.timezone / -3600)
    packet = bytearray(0x30)

    year = datetime.now().year

    if timezone < 0:
        packet[0x08] = 0xff + timezone - 1
        packet[0x09] = 0xff
        packet[0x0a] = 0xff
        packet[0x0b] = 0xff
    else:
        packet[0x08] = timezone
        packet[0x09] = 0
        packet[0x0a] = 0
        packet[0x0b] = 0
    packet[0x0c] = year & 0xff
    packet[0x0d] = year >> 8
    packet[0x0e] = datetime.now().minute
    packet[0x0f] = datetime.now().hour
    subyear = str(year)[2:]
    packet[0x10] = int(subyear)
    packet[0x11] = datetime.now().isoweekday()
    packet[0x12] = datetime.now().day
    packet[0x13] = datetime.now().month
    packet[0x18] = int(address[0])
    packet[0x19] = int(address[1])
    packet[0x1a] = int(address[2])
    packet[0x1b] = int(address[3])
    packet[0x1c] = port & 0xff
    packet[0x1d] = port >> 8
    packet[0x26] = 6
    checksum = 0xbeaf

    for i in range(len(packet)):
        checksum += packet[i]
    checksum = checksum & 0xffff
    packet[0x20] = checksum & 0xff
    packet[0x21] = checksum >> 8

    cs.sendto(packet, ('255.255.255.255', 80))
    if timeout is None:
        response = cs.recvfrom(1024)
        responsepacket = bytearray(response[0])
        host = response[1]
        mac = responsepacket[0x3a:0x40]
        devtype = responsepacket[0x34] | responsepacket[0x35] << 8

        return gendevice(devtype, host, mac)

    while (time.time() - starttime) < timeout:
        cs.settimeout(timeout - (time.time() - starttime))
        try:
            response = cs.recvfrom(1024)
        except socket.timeout:
            return devices
        responsepacket = bytearray(response[0])
        host = response[1]
        devtype = responsepacket[0x34] | responsepacket[0x35] << 8
        mac = responsepacket[0x3a:0x40]
        dev = gendevice(devtype, host, mac)
        devices.append(dev)
    return devices


class device:
    def __init__(self, host, mac, devtype, timeout=10):
        self.host = host
        self.mac = mac.encode() if isinstance(mac, str) else mac
        self.devtype = devtype
        self.timeout = timeout
        self.count = random.randrange(0xffff)
        self.iv = bytearray(
            [0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58])
        self.id = bytearray([0, 0, 0, 0])
        self.cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.cs.bind(('', 0))
        self.type = "Unknown"
        self.lock = threading.Lock()

        self.aes = None
        key = bytearray(
            [0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02])
        self.update_aes(key)

    def update_aes(self, key):
        self.aes = Cipher(algorithms.AES(key), modes.CBC(self.iv),
                          backend=default_backend())

    def encrypt(self, payload):
        encryptor = self.aes.encryptor()
        return encryptor.update(payload) + encryptor.finalize()

    def decrypt(self, payload):
        decryptor = self.aes.decryptor()
        return decryptor.update(payload) + decryptor.finalize()

    def auth(self):
        payload = bytearray(0x50)
        payload[0x04] = 0x31
        payload[0x05] = 0x31
        payload[0x06] = 0x31
        payload[0x07] = 0x31
        payload[0x08] = 0x31
        payload[0x09] = 0x31
        payload[0x0a] = 0x31
        payload[0x0b] = 0x31
        payload[0x0c] = 0x31
        payload[0x0d] = 0x31
        payload[0x0e] = 0x31
        payload[0x0f] = 0x31
        payload[0x10] = 0x31
        payload[0x11] = 0x31
        payload[0x12] = 0x31
        payload[0x1e] = 0x01
        payload[0x2d] = 0x01
        payload[0x30] = ord('T')
        payload[0x31] = ord('e')
        payload[0x32] = ord('s')
        payload[0x33] = ord('t')
        payload[0x34] = ord(' ')
        payload[0x35] = ord(' ')
        payload[0x36] = ord('1')

        response = self.send_packet(0x65, payload)

        payload = self.decrypt(response[0x38:])

        if not payload:
            return False

        key = payload[0x04:0x14]
        if len(key) % 16 != 0:
            return False

        self.id = payload[0x00:0x04]
        self.update_aes(key)

        return True

    def get_type(self):
        return self.type

    def send_packet(self, command, payload):
        self.count = (self.count + 1) & 0xffff
        packet = bytearray(0x38)
        packet[0x00] = 0x5a
        packet[0x01] = 0xa5
        packet[0x02] = 0xaa
        packet[0x03] = 0x55
        packet[0x04] = 0x5a
        packet[0x05] = 0xa5
        packet[0x06] = 0xaa
        packet[0x07] = 0x55
        packet[0x24] = 0x2a
        packet[0x25] = 0x27
        packet[0x26] = command
        packet[0x28] = self.count & 0xff
        packet[0x29] = self.count >> 8
        packet[0x2a] = self.mac[0]
        packet[0x2b] = self.mac[1]
        packet[0x2c] = self.mac[2]
        packet[0x2d] = self.mac[3]
        packet[0x2e] = self.mac[4]
        packet[0x2f] = self.mac[5]
        packet[0x30] = self.id[0]
        packet[0x31] = self.id[1]
        packet[0x32] = self.id[2]
        packet[0x33] = self.id[3]

        # pad the payload for AES encryption
        if payload:
            numpad = (len(payload) // 16 + 1) * 16
            payload = payload.ljust(numpad, b"\x00")

        checksum = 0xbeaf
        for i in range(len(payload)):
            checksum += payload[i]
            checksum = checksum & 0xffff

        payload = self.encrypt(payload)

        packet[0x34] = checksum & 0xff
        packet[0x35] = checksum >> 8

        for i in range(len(payload)):
            packet.append(payload[i])

        checksum = 0xbeaf
        for i in range(len(packet)):
            checksum += packet[i]
            checksum = checksum & 0xffff
        packet[0x20] = checksum & 0xff
        packet[0x21] = checksum >> 8

        start_time = time.time()
        with self.lock:
            while True:
                try:
                    self.cs.sendto(packet, self.host)
                    self.cs.settimeout(1)
                    response = self.cs.recvfrom(2048)
                    break
                except socket.timeout:
                    if (time.time() - start_time) > self.timeout:
                        raise
        return bytearray(response[0])

class sp4(device):
    def __init__(self, host, mac, devtype, timeout=5):
        device.__init__(self, host, mac, devtype, timeout)
        self.type = "SP4"

    def get_state(self):
        """Get state of device"""
        packet = self._encode(1, b'{}')
        response = self.send_packet(0x6a, packet)
        return self._decode(response)
        
    def set_state_dict(self, data):
        js = json.dumps(data).encode('utf8')
        packet = self._encode(2, js)
        response = self.send_packet(0x6a, packet)
        return self._decode(response)
        
    def set_state(self, pwr=None, ntlight=None, indicator=None, ntlbrightness=None, maxworktime=None):
        """Set state of device"""
        data = {}
        if pwr is not None:
            data['pwr'] = int(bool(pwr))
        if ntlight is not None:
            data['ntlight'] = int(bool(ntlight))
        if indicator is not None:
            data['indicator'] = int(bool(indicator))
        if ntlbrightness is not None:
            data['ntlbrightness'] = ntlbrightness
        if maxworktime is not None:
            data['maxworktime'] = maxworktime
        
        return self.set_state_dict(data)

    def set_power(self, state):
        """Sets the power state of the smart plug"""
        return self.set_state(pwr = int(bool(state)))

    def set_nightlight(self, state):
        """Sets the night light state of the smart plug"""
        return self.set_state(ntlight = int(bool(state)))

    def check_power(self):
        """Returns the power state of the smart plug."""
        state = self.get_state()
        if(state):
            return state["pwr"]

    def check_nightlight(self):
        """Returns the night light state of the smart plug."""
        state = self.get_state()
        if(state):
            return state["ntlight"]


    def _encode(self, flag, js):
        # SP4 support added by Petter Olofsson
        # packet format is:
        # 0x00-0x03 header 0xa5a5, 0x5a5a
        # 0x04-0x05 "0xbeaf" checksum
        # 0x06 flag (1 for read or 2 write?)
        # 0x07 unknown (0xb)
        # 0x08-0x0b length of json
        # 0x0c- json data
        packet = bytearray(14)
        struct.pack_into('<HHHBBI', packet, 0, 0xa5a5, 0x5a5a, 0x0000, flag, 0x0b, len(js))
        for i in range(len(js)):
            packet.append(js[i])

        checksum = 0xbeaf
        for c in packet:
            checksum = (checksum + c) & 0xffff
        packet[0x04] = checksum & 0xff
        packet[0x05] = checksum >> 8
        return packet

    def _decode(self, response):
        err = response[0x22] | (response[0x23] << 8)
        if err != 0:
            return None

        payload = self.decrypt(bytes(response[0x38:]))
        js_len = struct.unpack_from('<I', payload, 0x08)[0]
        state = json.loads(payload[0x0c:0x0c+js_len])
        return state

class sp2(device):
    def __init__(self, host, mac, devtype):
        device.__init__(self, host, mac, devtype)
        self.type = "SP2"

    def set_power(self, state):
        """Sets the power state of the smart plug."""
        packet = bytearray(16)
        packet[0] = 2
        if self.check_nightlight():
            packet[4] = 3 if state else 2
        else:
            packet[4] = 1 if state else 0
        self.send_packet(0x6a, packet)

    def set_nightlight(self, state):
        """Sets the night light state of the smart plug"""
        packet = bytearray(16)
        packet[0] = 2
        if self.check_power():
            packet[4] = 3 if state else 1
        else:
            packet[4] = 2 if state else 0
        self.send_packet(0x6a, packet)

    def check_power(self):
        """Returns the power state of the smart plug."""
        packet = bytearray(16)
        packet[0] = 1
        response = self.send_packet(0x6a, packet)
        err = response[0x22] | (response[0x23] << 8)
        if err != 0:
            return None
        payload = self.decrypt(bytes(response[0x38:]))
        if isinstance(payload[0x4], int):
            return bool(payload[0x4] == 1 or payload[0x4] == 3 or payload[0x4] == 0xFD)
        return bool(ord(payload[0x4]) == 1 or ord(payload[0x4]) == 3 or ord(payload[0x4]) == 0xFD)

    def check_nightlight(self):
        """Returns the power state of the smart plug."""
        packet = bytearray(16)
        packet[0] = 1
        response = self.send_packet(0x6a, packet)
        err = response[0x22] | (response[0x23] << 8)
        if err != 0:
            return None
        payload = self.decrypt(bytes(response[0x38:]))
        if isinstance(payload[0x4], int):
            return bool(payload[0x4] == 2 or payload[0x4] == 3 or payload[0x4] == 0xFF)
        return bool(ord(payload[0x4]) == 2 or ord(payload[0x4]) == 3 or ord(payload[0x4]) == 0xFF)

    def get_energy(self):
        packet = bytearray([8, 0, 254, 1, 5, 1, 0, 0, 0, 45])
        response = self.send_packet(0x6a, packet)
        err = response[0x22] | (response[0x23] << 8)
        if err != 0:
            return None
        payload = self.decrypt(bytes(response[0x38:]))
        if isinstance(payload[0x7], int):
            energy = int(hex(payload[0x07] * 256 + payload[0x06])[2:]) + int(hex(payload[0x05])[2:]) / 100.0
        else:
            energy = int(hex(ord(payload[0x07]) * 256 + ord(payload[0x06]))[2:]) + int(
                hex(ord(payload[0x05]))[2:]) / 100.0
        return energy

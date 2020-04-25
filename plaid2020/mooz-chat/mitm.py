import string
import requests
import base64
import jwt
import json
import threading
import asyncio
from queue import Queue
import time
import codecs

from aiortc.contrib.signaling import object_from_string, object_to_string
from aiortc import (
    RTCIceCandidate,
    RTCConfiguration,
    RTCIceCandidate,
    RTCPeerConnection,
    RTCSessionDescription,
    RTCIceServer,
)

MY_IP = 'your ip here'
JWT = "Pl4idC7F2020"

rtcConfiguration = RTCConfiguration(iceServers=[RTCIceServer("turn:45.79.56.244", username="user", credential="passpass")])

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)

def get(url, username):
    url = "https://chat.mooz.pwni.ng%s" % url
    token = {'ipaddr': MY_IP, 'username': username}
    headers = {
        "x-chat-authorization": jwt.encode(token, JWT),
    }
    r=requests.get(url, headers=headers)
    assert r.status_code in (200, 201), r.text
    s = r.text
    if s:
        return json.loads(s)

def post(url, data, username):
    url = "https://chat.mooz.pwni.ng%s" % url
    token = {'ipaddr': MY_IP, 'username': username}
    headers = {
        "x-chat-authorization": jwt.encode(token, JWT),
    }
    r=requests.post(url, headers=headers, data=json.dumps(data))
    assert r.status_code in (200, 201), r.text
    s = r.text
    if s:
        return json.loads(s)

def send_message(_from, to, type, data):
    post("/api/message", {"to": to, "type": type, "data": data}, _from)

def get_messages_thread(queue, username):
    while True:
        message = get("/api/message", username)
        queue.put(message)

def get_rooms():
    return get("/api/rooms", "tomnook")

def fix_candidate(candidate):
    return json.dumps({"candidate": json.loads(candidate)["candidate"], "sdpMid": 0, "sdpMLineIndex": 0})

def fix_candidate2(candidate):
    return json.dumps({"type": "candidate", "candidate": json.loads(candidate)["candidate"], "id": 0, "label": 0})

class Channel(object):
    def __init__(self, channel):
        self.channel = channel
        @channel.on("open")
        def on_open():
            self.on_open()

        @channel.on("message")
        def on_message(message):
            self.on_message(message)
        
        self.open_event = asyncio.Event()
        self.queue = asyncio.Queue()

    def on_open(self):
        print("Channel open!")
        self.open_event.set()

    def on_message(self, message):
        self.queue.put_nowait(message)
    
    def wait(self):
        run(self.open_event.wait())
        
    def recv(self):
        return run(self.queue.get())

    def send(self, data):
        self.channel.send(data)

def join_room(room, username):
    queue=Queue()
    threading.Thread(target=get_messages_thread, args=(queue, username)).start()
    room_info = get("/api/find/%s" % room, username)
    print("Got room info: %s" % room_info)
    rtc = RTCPeerConnection(rtcConfiguration)
    channel = Channel(rtc.createDataChannel("data", negotiated=True, id=0))

    run(rtc.setRemoteDescription(object_from_string(room_info["offer"])))
    answer = run(rtc.createAnswer())
    run(rtc.setLocalDescription(answer))
    print("Answer: %s" % object_to_string(answer))
    post("/api/join/%s" % room, {"answer": object_to_string(answer)}, username)
    for candidate in rtc.sctp.transport.transport.iceGatherer.getLocalCandidates():
        send_message(username, room_info["username"], "ice", fix_candidate(object_to_string(candidate)))
    time.sleep(3)
    while not queue.empty():
        for message in queue.get():
            if message["type"] == "ice":
                print("Got candidate: %s" % message["data"])
                rtc.sctp.transport.transport.addRemoteCandidate(object_from_string(fix_candidate2(message["data"])))
    return channel, rtc


def host_room(room, username):
    queue=Queue()
    threading.Thread(target=get_messages_thread, args=(queue, username)).start()
    rtc = RTCPeerConnection(rtcConfiguration)
    channel = Channel(rtc.createDataChannel("data", negotiated=True, id=0))

    offer = run(rtc.createOffer())
    run(rtc.setLocalDescription(offer))
    res = post("/api/host/%s" % room, {"room": room, "offer": object_to_string(offer)}, username)
    print("Got res %s" % res)
    run(rtc.setRemoteDescription(object_from_string(res["answer"])))
    for candidate in rtc.sctp.transport.transport.iceGatherer.getLocalCandidates():
        send_message(username, res["username"], "ice", fix_candidate(object_to_string(candidate)))
    time.sleep(3)
    while not queue.empty():
        for message in queue.get():
            if message["type"] == "ice":
                print("Got candidate: %s" % message["data"])
                rtc.sctp.transport.transport.addRemoteCandidate(object_from_string(fix_candidate2(message["data"])))
    rtc.sctp.transport.transport.addRemoteCandidate(None)

    return channel, rtc

rooms = get_rooms()
print("Got rooms: %s" % rooms)
if rooms[0]['host'].startswith("timmy_"):
    print("join room %s" % rooms[0]['host'])
    channel_1, rtc1 = join_room(rooms[0]['room'], rooms[0]['host'].replace("timmy","tommy"))
    channel_2, rtc2 = host_room(rooms[0]['room'], rooms[0]['host']) 
    # Activate the first channel
    rtc1.sctp.transport.transport.addRemoteCandidate(None)
    channel_1.wait()
    while True:
        if not channel_1.queue.empty():
            m = channel_1.recv()
            print("H: %s" % codecs.encode(m, "hex"))
            channel_2.send(m)
        if not channel_2.queue.empty():
            m = channel_2.recv()
            print("C: %s" % codecs.encode(m, "hex"))
            channel_1.send(m)
        run(asyncio.sleep(0.1))

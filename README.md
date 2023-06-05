# CS118 Project 2

This is the repo for spring23 cs118 project 2.
The Docker environment has the same setting with project 0.

## Project Report

### <ins>Team members:</ins>
- Lime Yao (UID: ___ ___ ___)
- Ryan Lee (UID: ___ ___ ___)
- Trung Vu (UID: 705 586 785)

### <ins>High level decription of router</ins>
This project simulates a virtual home router by using NAT/NAPT to separate the Internet (WAN) from the home network (LAN).

We started our program as a server that listens to port 5152 and accepts multiple connections. We receive IPv4 packets through these connections and have to forward, rewrite, or drop them depending on the context. When we detect there to be incoming data from a client, we receive the packet information and analyze it.  
### <ins>Problems ran into and how we solved them</ins>
- How exactly select() worked
  - Going to discussion section helped us figure this out
- Bind: address already in use
  - Set the option SO_REUSEADDR to allow the reuse of local addresses 
  - Set the option SO_REUSEPORT to allow multiple sockets to be bound to an indentical socket address 
- Misunderstanding 10.0.0.10
  - Initially thought that 10.0.0.10 represented WAN IP address 0.0.0.0. It does not. 10.0.0.10 is simply a random address outside the local network. When sending from LAN to address outside LAN, forward to WAN.
- How to understand the hex code output when running into an error on local tests
  - Used the RFC files linked on the project spec and broke down what each hex code corresponded to.
  - We then used packet_generate.py to see what output we should be expecting when running the local tests. This helped us understand what exactly we were getting wrong (i.e. src/dest addr, TCP/UDP checksum, etc.)
- Understanding the format of the data
  - We didn't know where the TCP/UDP header started in relation to the IP header
  - We did some digging into textbooks, websites, and etc. to learn the following:
    - We have IP header
    - Payload of IP header is the TCP/UDP
    - TCP/UDP header starts at the beginning of IP payload
    - TCP/UDP payloads starts at the end of the TCP/UDP header
- Dropping packets based on ttl value
  - We were decrementing ttl, but didn't know when to drop the packet. You drop packet when ttl <= 1
- NAPT table coding
  - We first programmed the NAPT table to fit for static NAPT cases. Modifying the NAPT code to fit the dynamic NAPT cases proved difficult because the original code we wrote was fairly messy and inflexible
  - We rewrote the code for the NAPT table, separating certain sections, creating helper functions for repeating code, and taking a different approach that accomodated both static and dynamic cases
- Sending the updated data
  - Our approach extracted data and put it into local variables of type iphdr and tcphdr/udphdr so we can use the properties of those types to easily update the fields we needed to update (i.e. checksum, port, src/dest addr, etc.). We proceeded to update these local variables, but ultimately sent the unmodified data instead.
  - Understanding that we were sending the wrong data, we not bumped into another issue. We had two things we had to send: (1) iphdr (2) tcphdr/ucphdr. We decided to use send() twice. Once for iphdr and another for either tcphdr or udphdr.
- Checksum calculation incorrect
  - We realized we used uint32_t when we should've been using uint16_t
  - We didn't understand what exactly we had to include when calculating UDP/TCP checksum. Watching YouTube videos and going through Piazza helped us understand what we had to include.
  - We only parsed the UDP/TCP header and NOT the payload when calculating checksum. Modifying the code to parse through the UDP/TCP payload solved this issue.
  - We never accounted for payloads or headers having an odd length. Adding code to get the last 8-bits of a payload or header and using bit-masking to add the correct value to checksum solved the issue.
  - We parsed the UDP/TCP header and payload incorrectly. We discovered it was a silly for-loop conditional mistake and upon fixing it, we got the code to work properly.

### <ins>Acknowledgement of any online tutorials or code examples (except class website) in no particular order</ins>
- Handling multiple connections using select()
  - https://www.geeksforgeeks.org/socket-programming-in-cc-handling-multiple-clients-on-server-without-multi-threading/#
- Calculating UDP checksum
  - https://www.youtube.com/watch?v=rYVHBICiiEc
- Calculating checksum when payload is odd length (expired site contents put on github link)
  - https://stackoverflow.com/questions/8845178/c-programming-tcp-checksum/51269953#51269953
  - https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
- Start code from TA
  - 1b-starter-main.cpp (found in Bruinlearn)
- Man pages for libraries and functions
  - https://man7.org/linux/man-pages/man7/socket.7.html
  - https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.7-4.6/+/refs/heads/tools_r20/sysroot/usr/include/netinet/ip.h
  - https://android.googlesource.com/platform/bionic/+/f8a2243/libc/include/netinet/udp.h
  - https://android.googlesource.com/platform/bionic/+/master/libc/include/netinet/tcp.h
- Packet format files linked on Project Spec
  - https://datatracker.ietf.org/doc/html/rfc791
  - https://www.rfc-editor.org/rfc/rfc768.html
  - https://www.rfc-editor.org/rfc/rfc9293.html

###########################################################

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Provided Files

- `project` is the folder to develop codes for future projects.
- `grader` contains an autograder for you to test your program.
- `scenarios` contains test cases and inputs to your program.
- `docker-compose.yaml` and `Dockerfile` are files configuring the containers.

## Docker bash commands

```bash
# Setup the container(s) (make setup)
docker compose up -d

# Bash into the container (make shell)
docker compose exec node1 bash

# Remove container(s) and the Docker image (make clean)
docker compose down -v --rmi all --remove-orphans
```

## Environment

- OS: ubuntu 22.04
- IP: 192.168.10.225. NOT accessible from the host machine.
- Files in this repo are in the `/project` folder. That means, `server.cpp` is `/project/project/server.cpp` in the container.
  - When submission, `server.cpp` should be `project/server.cpp` in the `.zip` file.

## Project 2 specific

### How to use the test script

To test your program with the provided checker, go to the root folder of the repo and
run `python3 grader/executor.py <path-to-server> <path-to-scenario-file>`.  
For example, to run the first given test case, run the following command:
```bash
python3 grader/executor.py project/server scenarios/setting1.json
# Passed check point 1
# Passed check point 2
# OK
```

If your program passes the test, the last line of output will be `OK`.
Otherwise, the first unexpect/missing packet will be printed in hex.
Your program's output to `stdout` and `stderr` will be saved to `stdout.txt` and `stderr.txt`, respectively.
You can use these log files to help you debug your router implementation.
You can also read `executor.py` and modify it (like add extra outputs) to help you.
We will not use the grader in your submitted repo for grading.

### How to write a test scenario

A test scenario is written in a JSON file. There are 5 example test cases in the `scenarios` folder.
The fields of the JSON file are:

- `$schema`: Specify the JSON schema file so your text editor can help you validate the format.
  Should always point to `setting_schema.json`.
- `input`: Specify the input file to the program. Should use relative path to the JSON file.
- `actions`: A list of actions taken in the test scenario. There are 3 types of actions:
  - `send`: Send a TCP/UDP packet at a specified port (`port`).
  - `expect`: Expect to receive a TCP/UDP packet at a specified port (`port`).
  - `check`: Delay for some time for your server to process (`delay`, in seconds).
    Then, check if all expectations are satisfied.
    All packets received since the last checkpoint must be exactly the same as specified in `expect` instructions.
    There should be no unexpected or missing packets
  - The last action of `actions` must be `check`.
- The fields of a packet include:
  - `port`: The ID of the router port to send/receive the packet, not the port number.
  The port numbers are specified in `src_port` and `dst_port`.
  - `src_ip` and `src_port`: The source IP address and port number.
  - `dst_ip` and `dst_port`: The destination IP address and port number.
  - `proto`: The transport layer protocol. Can only be `tcp` or `udp`.
  - `payload`: The application layer payload of the packet. Must be a string.
  - `ttl`: Hop limit of the packet.
  - `seq`: TCP sequence number.
  - `ack`: TCP acknowledge number.
  - `flag`: The flag field in TCP header. Should be specified in numbers. For example, ACK should be `16`.
  - `rwnd`: TCP flow control window.
  - `ip_options_b64`: The IP options. Must be encoded in base64 if specified.
  - `ip_checksum`: The checksum for an IP packet. Automatically computed to be the correct number if not specified.
  - `trans_checksum`: The checksum in the TCP/UDP header. Automatically computed to be the correct number if not specified.
  - Most of these fields are optional, but omitting mandatory fields may crash the grader.

Please read the example JSON files and the schema JSON for details.

### How to examine a test scenario

To print all packets in a test scenario in hex format,
run `python3 grader/packet_generate.py` and input the JSON setting.
You may also use `<` to redirect the input to the JSON file, like
```bash
python3 grader/packet_generate.py < scenarios/setting1.json
# ================== SEND @@ 01 ==================
# 45 00 00 1c 00 00 40 00  40 11 b6 54 c0 a8 01 64 
# c0 a8 01 c8 13 88 17 70  00 08 50 69
# ================== ========== ==================
#
# ================== RECV @@ 02 ==================
# 45 00 00 1c 00 00 40 00  3f 11 b7 54 c0 a8 01 64 
# c0 a8 01 c8 13 88 17 70  00 08 50 69
# ================== ========== ==================
#
# Check point 1
#
# ================== SEND @@ 01 ==================
# 46 00 00 20 00 00 40 00  40 11 b4 4f c0 a8 01 64 
# c0 a8 01 c8 01 01 00 00  13 88 17 70 00 08 50 69
# ================== ========== ==================
#
# ================== RECV @@ 02 ==================
# 46 00 00 20 00 00 40 00  3f 11 b5 4f c0 a8 01 64 
# c0 a8 01 c8 01 01 00 00  13 88 17 70 00 08 50 69
# ================== ========== ==================
#
# Check point 2
#
```

### Other notes

- We will use a different version of grader for the final test to integrate with Gradescope.
  But it will be similar to the given one.
  Modifying the grader in this repo will not affect anything.
- We will include many hidden test cases in the final test. Do not fully depend on the 5 given ones.
  They do not cover all edge cases that we want to test.
- The autograder will only build your program in the `project` folder, and grade the built `server` executable.
  Your program should not depend on other files to run.
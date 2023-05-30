#include <iostream>
#include <string>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <vector>

#define MAXCLIENTS 30
#define BUFFER_SIZE 2048
#define DEFAULT_PORT 5152





int main(int argc, char *argv[]) {
    std::string szLine;

    // First line is the router's LAN IP and the WAN IP
    std::getline(std::cin, szLine);
    size_t dwPos = szLine.find(' ');
    auto szLanIp = szLine.substr(0, dwPos);
    auto szWanIp = szLine.substr(dwPos + 1);
    
    std::cout << "Server's LAN IP: " << szLanIp << std::endl
              << "Server's WAN IP: " << szWanIp << std::endl;
    
    std::string IPClients[MAXCLIENTS];

    //counter needed for determining number of connections to accept
    int hostCounter = 0;

    while (szLine != ""){
        std::getline(std::cin, szLine);
        IPClients[hostCounter] = szLine;
        hostCounter++;
    }

    int listening_socket, new_socket, client_sockets[MAXCLIENTS], sd, max_sd;
    int activity, addrlen, valread;
    struct sockaddr_in address;
    fd_set readfds;
    char buffer[BUFFER_SIZE];

    for (int i = 0; i < MAXCLIENTS; i++) {
        client_sockets[i] = 0;
    }

    listening_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listening_socket == 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(DEFAULT_PORT);

    if (bind(listening_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(listening_socket, 10) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Waiting for clients on port %d...\n", DEFAULT_PORT);

    addrlen = sizeof(address);

    //accept (hostCounter - 1) number of connections
    for (int i = 0; i < hostCounter - 1; i++){
        new_socket = accept(listening_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);

        if (new_socket < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        printf("Client connected, ip: %s, port: %d\n",
                inet_ntoa(address.sin_addr), ntohs(address.sin_port));
        
        //add to client_sockets to be used in select() later
        for (int i = 0; i < MAXCLIENTS; i++) {
            if (client_sockets[i] == 0) {
                client_sockets[i] = new_socket;
                std::cout << "client's virtual ip address: " << IPClients[i] << std::endl;
                break;
            }
        }
    }

    while (1) {
        //zero out the fd_set each loop
        FD_ZERO(&readfds);

        // Include *connected* sockets for clients (those are not 0)
        for (int i = 0; i < MAXCLIENTS; i++) {
            sd = client_sockets[i];

            if (sd > 0) {
                FD_SET(sd, &readfds);
            }

            // Keep track of the maximum value of the included file descriptors
            if (sd > max_sd) {
                max_sd = sd;
            }
        }
        
        //select() zeros out every fds in fd_set except those that had event 
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) {
            perror("select");
        }
        // Check the connection sockets to see if there is incoming data from
        // each client
        for (int i = 0; i < MAXCLIENTS; i++) {
            sd = client_sockets[i];

            if (sd > 0 && FD_ISSET(sd, &readfds)) {
                // Receive data from client if there is data
                std::cout << "Receiving data from: " << IPClients[i] << std::endl;
                valread = recv(sd, buffer, BUFFER_SIZE, 0);
                std::cout << "read: " << valread << " bytes" << std::endl;
                buffer[valread] = '\0';
                printf("Client %d: %s\n", i, buffer);   

                //packet information extraction/analysis (snippet from 1b-starter-main.cpp)
                std::vector<uint8_t> pkt(buffer, buffer + valread);
                auto incomingIpHdr = reinterpret_cast<iphdr*>(pkt.data());
                auto totLen = static_cast<size_t>(ntohs(incomingIpHdr->tot_len));
                std::cout << "totalLen: "<< totLen << std::endl;
                std::cout << "protocol: " << static_cast<size_t>(incomingIpHdr->protocol) << std::endl;
                auto hdrLen = static_cast<size_t>(incomingIpHdr->ihl) * 4;
                std::cout << "headerLen: " << hdrLen << std::endl;
                
                auto ttl = static_cast<size_t>(incomingIpHdr->ttl);
                std::cout << "ttl: " << ttl << std::endl;
                incomingIpHdr->ttl -= 1;

                std::cout << "checksum (before): " << incomingIpHdr->check << std::endl;
                // The checksum field is the 16 bit one's complement of the one's
                // complement sum of all 16 bit words in the header.  For purposes of
                // computing the checksum, the value of the checksum field is zero.
                uint32_t sum = 0;
                incomingIpHdr->check = 0;
                for (uint32_t i = 0; i < hdrLen; i += 2) {
                auto headerword = reinterpret_cast<uint16_t*>(pkt.data() + i);
                sum += *headerword;
                // sum += ntohs(*headerword);
                }
                while (sum >> 16) {
                sum = (sum & 0xffff) + (sum >> 16);
                }
                // one's complement
                sum = ~sum;
                incomingIpHdr->check = sum;
                // incomingIpHdr->check = htons(sum);
                std::cout << "checksum (after): " << incomingIpHdr->check << std::endl;

                //source/destination addresses
                char saddr[16];
                char daddr[16];
                snprintf(saddr, 16, "%pI4", &incomingIpHdr->saddr); // Mind the &!
                snprintf(daddr, 16, "%pI4", &incomingIpHdr->daddr); // Mind the &!

                // auto saddr = static_cast<size_t>(ntohs(incomingIpHdr->saddr));
                // auto daddr = static_cast<size_t>(ntohs(incomingIpHdr->daddr));

                std::cout << "source address: " << saddr << " destination address: " << daddr << std::endl;
                if (incomingIpHdr->protocol == IPPROTO_TCP) {
                std::cout << "This is a TCP packet" << std::endl;
                auto incomingTcpHdr = reinterpret_cast<tcphdr*>(pkt.data() + hdrLen);
                auto sourcePort = static_cast<size_t>(ntohs(incomingTcpHdr->th_sport));
                auto destPort = static_cast<size_t>(ntohs(incomingTcpHdr->th_dport));
                std::cout << "sourePort: "<< sourcePort << " destPort: "<< destPort << std::endl;
                auto tcpHdrLen = static_cast<size_t>(incomingTcpHdr->th_off) * 4;
                std::cout << "payloadLen: "<< totLen - hdrLen - tcpHdrLen << std::endl;
                }
                else if (incomingIpHdr->protocol == IPPROTO_UDP) {
                std::cout << "This is a UDP packet" << std::endl;
                auto incomingUdpHdr = reinterpret_cast<udphdr*>(pkt.data() + hdrLen);
                auto sourcePort = static_cast<size_t>(ntohs(incomingUdpHdr->uh_sport));
                auto destPort = static_cast<size_t>(ntohs(incomingUdpHdr->uh_dport));
                std::cout << "sourePort: "<< sourcePort << " destPort: "<< destPort << std::endl;
                }


                send(client_sockets[2], pkt.data(), pkt.size(), 0);
                
            }
        }
    }

    return 0;
}

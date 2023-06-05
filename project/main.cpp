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
#include <unordered_map>
using namespace std;

#define MAXCLIENTS 30
#define BUFFER_SIZE 2048
#define DEFAULT_PORT 5152
#define DYNAMIC_PORT_START 49152

//information contained in each entry in NAPT table
struct napt_entry{
    std::string lan_ip;
    std::string wan_ip; // will be the same IP for every entry
    int lan_port;
    int wan_port;
};

void update_checksum(uint16_t &checksum, size_t hdrLen, uint8_t *pktData, uint32_t psuedoHeader = 0) {
    // The checksum field is the 16 bit one's complement of the one's
    // complement sum of all 16 bit words in the header.  For purposes of
    // computing the checksum, the value of the checksum field is zero.
    uint32_t checksumAfter = 0;
    uint32_t i = 0;
    for (; i < hdrLen - 1; i += 2) {
        auto headerword = reinterpret_cast<uint16_t*>(pktData + i);
        checksumAfter += *headerword;
    }
    if ((hdrLen) % 2){
        auto headerword = reinterpret_cast<uint16_t*>(pktData + i); //not sure about here; i think that makes sense
        checksumAfter += (*headerword)&htons(0xFF00); // i think?? the rest should be fine let me run it
    }
    
    checksumAfter += psuedoHeader;
    
    while (checksumAfter >> 16)
        checksumAfter = (checksumAfter & 0xffff) + (checksumAfter >> 16);
    
    checksumAfter = ~checksumAfter; /* 1's complement */
    checksum = checksumAfter;
}

int main(int argc, char *argv[]) {
    std::string szLine;

    // First line is the router's LAN IP and the WAN IP
    std::getline(std::cin, szLine);
    size_t dwPos = szLine.find(' ');
    auto szLanIp = szLine.substr(0, dwPos);
    auto szWanIp = szLine.substr(dwPos + 1);
    
    std::cout << "Server's LAN IP: " << szLanIp << std::endl
              << "Server's WAN IP: " << szWanIp << std::endl;

    struct in_addr lanIP;
    inet_aton(szLanIp.c_str(), &lanIP);    
    
    std::string IPClients[MAXCLIENTS];
    napt_entry napt_table[MAXCLIENTS];
    // counter needed for determining number of connections to accept
    int hostCounter = 0;
    
    // parse IP configuration
    std::getline(std::cin, szLine);
    while (szLine != "") {
        IPClients[hostCounter] = szLine;
        hostCounter++;
        std::getline(std::cin, szLine);
    }
    
    // parse Static NAPT table
    std::cout << "Parsing NAPT Table..." << std::endl;
    std::string delimiter = " ";
    std::string infoPerLine[3];
    int tableEntryNum = 0;
    int dynamicEntrynum = 0;
    
    std::getline(std::cin, szLine);    
    while (szLine != "") {
        napt_entry entry;
        for (int i = 0; i < 3; i++){
            infoPerLine[i] = szLine.substr(0, szLine.find(delimiter));
            szLine.erase(0, szLine.find(delimiter) + delimiter.length());
        }
        
        entry.lan_ip = infoPerLine[0];
        entry.wan_ip = szWanIp;
        entry.lan_port = stoi(infoPerLine[1]);
        entry.wan_port = stoi(infoPerLine[2]);

        napt_table[tableEntryNum] = entry;
        tableEntryNum++;
        std::getline(std::cin, szLine);
    }

    for (int i = 0; i < tableEntryNum; i++)
        std::cout << "entry " << i << ": (" << napt_table[i].lan_ip << ", " 
                                           << napt_table[i].lan_port << ") -> ("
                                           << napt_table[i].wan_ip << ", " 
                                           << napt_table[i].wan_port << ")" << std::endl;

    int listening_socket, new_socket, sd, max_sd;
    int activity, addrlen, valread;
    struct sockaddr_in address;
    fd_set readfds;
    char buffer[BUFFER_SIZE];
    std::unordered_map<std::string, int> client_sockets; /* maps client IP to associated socket file descriptor */
    
    if (listening_socket = socket(AF_INET, SOCK_STREAM, 0); listening_socket == 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(DEFAULT_PORT);

    // ADDED CODE ELIMINATES BIND: ADDR ALREADY IN USE ERROR; GIVES RUN-TIME ERRORS IN GRADESCOPE
    const int yes = 1;
    if (setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0){
        perror("server: setsockopt");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(listening_socket, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int)) < 0){
        perror("server: setsockopt");
        exit(EXIT_FAILURE);
    }

    if (bind(listening_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(listening_socket, 10) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Waiting for %d clients on port %d...\n", hostCounter, DEFAULT_PORT);

    addrlen = sizeof(address);

    // accept same number of connections as hostCounter
    for (int i = 0; i < hostCounter; i++){
        new_socket = accept(listening_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);

        if (new_socket < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        printf("Client connected, ip: %s, port: %d\n",
                inet_ntoa(address.sin_addr), ntohs(address.sin_port));
        
        // add to client_sockets to be used in select() later
        client_sockets[IPClients[i]] = new_socket;
        std::cout << "client's virtual ip address: " << IPClients[i] << std::endl;
    }

    while (1) {
        FD_ZERO(&readfds); /* remove all file descriptors from reading set */
        
        for (const auto &c: client_sockets) {
            sd = c.second;
            if (sd > 0)
                FD_SET(sd, &readfds); /* add valid file descriptor to reading set */
            if (sd > max_sd)
                max_sd = sd;
        }
        
        // select() zeros out every fds in fd_set except those that had event 
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR))
            perror("select");
        
        // Check the connection sockets to see if there is incoming data from each client
        for (const auto &c: client_sockets) {
            sd = c.second;

            if (sd > 0 && FD_ISSET(sd, &readfds)) {
                std::cout << std::endl;
                // Receive data from client if there is data
                valread = recv(sd, buffer, BUFFER_SIZE, 0);
                if (valread == 0) {
                    std::cout << "Closing link: " << c.first << std::endl;
                    close(sd);
                    client_sockets[c.first] = 0;
                    break;
                }
                std::cout << "Received " << valread << " bytes from " << c.first << std::endl;
                buffer[valread] = '\0';  

                // Packet information extraction/analysis (snippet from 1b-starter-main.cpp)
                std::vector<uint8_t> pkt(buffer, buffer + valread);
                auto incomingIpHdr = reinterpret_cast<iphdr*>(pkt.data());
                auto hdrLen = static_cast<size_t>(incomingIpHdr->ihl) * 4;
                std::cout << "hdrLen: "<< hdrLen << std::endl;

                auto totLen = static_cast<size_t>(ntohs(incomingIpHdr->tot_len));
                std::cout << "totalLen: "<< totLen << std::endl;                
                
                // calculate IP checksum
                std::cout << "checksum (before): " << static_cast<size_t>(incomingIpHdr->check);
                
                uint16_t ipcheck = incomingIpHdr->check;
                update_checksum(ipcheck, hdrLen, pkt.data());
                std::cout << ", checksum (after): " << ipcheck << std::endl;
                if (ipcheck != 0)
                    break; /* drop if checksum doesn't match */
                
                auto ttl = static_cast<size_t>(incomingIpHdr->ttl);
                std::cout << "ttl (before): " << ttl;
                if (ttl <= 1)
                    break; /* drop packet */
                incomingIpHdr->ttl -= 1;
                ttl = static_cast<size_t>(incomingIpHdr->ttl);
                cout << ", ttl (after): " << ttl << endl;
                
                // source and destination IP addresses
                struct in_addr source, destination;
                source.s_addr = incomingIpHdr->saddr;
                destination.s_addr = incomingIpHdr->daddr;                                
                std::cout << "source address: " << inet_ntoa(source) 
                          << ", destination address: " << inet_ntoa(destination) << std::endl;

                // my notes: incomingIpHdr --> addr
                //           incomingTCPHdr or incomingUDPHdr --> port #
                // struct format: lanip, wanip, lanPort, wanPort
                // if lan to lan don't need to translate anything
                
                if (incomingIpHdr->protocol == IPPROTO_TCP)
                    std::cout << "protocol: TCP" << std::endl;
                else if (incomingIpHdr->protocol == IPPROTO_UDP)
                    std::cout << "protocol: UDP" << std::endl;
                
                auto incomingTcpHdr = reinterpret_cast<tcphdr*>(pkt.data() + hdrLen);
                auto incomingUdpHdr = reinterpret_cast<udphdr*>(pkt.data() + hdrLen);
                
                // TCP/UDP checksum calculation
                uint32_t pseudo = 0;
                pseudo += (incomingIpHdr->saddr>>16) & 0xFFFF;
                pseudo += (incomingIpHdr->saddr) & 0xFFFF;
                pseudo += (incomingIpHdr->daddr>>16) & 0xFFFF;
                pseudo += (incomingIpHdr->daddr) & 0xFFFF;
                
                if (incomingIpHdr->protocol == IPPROTO_TCP) {
                    pseudo += htons(IPPROTO_TCP); //TCP protocol num 6
                    pseudo += htons(totLen - hdrLen); // tcp header + payload

                    uint16_t tcheck = incomingTcpHdr->th_sum;
                    std::cout << "tcpchecksum (before): " << static_cast<size_t>(incomingTcpHdr->th_sum);
                    update_checksum(tcheck, totLen - hdrLen, pkt.data() + hdrLen, pseudo);
                    std::cout << ", tcpchecksum (after): " << tcheck << std::endl;
                    if (tcheck != 0)
                        break; /* drop if checksum doesn't match */
                }
                else if (incomingIpHdr->protocol == IPPROTO_UDP) {
                    pseudo += htons(IPPROTO_UDP); //UDP protocol num 17
                    pseudo += incomingUdpHdr->uh_ulen;
                    
                    uint16_t ucheck = incomingUdpHdr->uh_sum;
                    std::cout << "udpchecksum (before): " << static_cast<size_t>(incomingUdpHdr->uh_sum);
                    update_checksum(ucheck, totLen - hdrLen, pkt.data() + hdrLen, pseudo);
                    std::cout << ", udpchecksum: " << ucheck << std::endl;
                    if (ucheck != 0)
                        break; /* drop if checksum doesn't match */
                }

                bool lanToWan = false;             

                // don't rewrite LAN -> LAN
                if (inet_netof(source) != inet_netof(destination)) {
                    uint16_t srcPort = 0;
                    uint16_t destPort = 0;
                    if (incomingIpHdr->protocol == IPPROTO_TCP) {
                        srcPort = ntohs(incomingTcpHdr->th_sport);
                        destPort = ntohs(incomingTcpHdr->th_dport);
                    }
                    else if (incomingIpHdr->protocol == IPPROTO_UDP) {
                        srcPort = ntohs(incomingUdpHdr->uh_sport);
                        destPort = ntohs(incomingUdpHdr->uh_dport);
                    }
                    bool entryFound = false;
                    int entry_ind = 0;
                    
                    // source is LAN
                    if (inet_netof(source) == inet_netof(lanIP)) {
                        lanToWan = true;
                        // scan NAPT for existing (IP, port) entry
                        for (int i = 0; i < tableEntryNum; i++) {
                            if (inet_ntoa(source) == napt_table[i].lan_ip 
                                && srcPort == napt_table[i].lan_port) {
                                entryFound = true;
                                entry_ind = i;
                                break;
                            }
                        }
                        if (!entryFound) {
                            napt_entry entry;
                            entry.lan_ip = inet_ntoa(source);
                            entry.lan_port = srcPort;
                            entry.wan_ip = szWanIp;
                            entry.wan_port = DYNAMIC_PORT_START + dynamicEntrynum;
                            napt_table[tableEntryNum] = entry;
                            std::cout << "Added new entry: (" << napt_table[tableEntryNum].lan_ip << ", " 
                                                          << napt_table[tableEntryNum].lan_port << ") -> ("
                                                          << napt_table[tableEntryNum].wan_ip << ", " 
                                                          << napt_table[tableEntryNum].wan_port << ")" << std::endl;
                            entryFound = true;
                            entry_ind = tableEntryNum;
                            tableEntryNum++;
                            dynamicEntrynum++;
                        }
                    }
                    // source is WAN
                    else {
                        for (int i = 0; i < tableEntryNum; i++) {
                            if (inet_ntoa(destination) == napt_table[i].wan_ip 
                                && destPort == napt_table[i].wan_port) {
                                entryFound = true;
                                entry_ind = i;
                                break;
                            }
                        }
                    }
                    
                    if (!entryFound)
                        break; /* drop unrecognized packets from WAN */
                    
                    // NAPT rewriting  
                    
                    // update address
                    std::string new_ip;
                    if (lanToWan) {
                        // sending from LAN; need to change to WAN
                        new_ip = napt_table[entry_ind].wan_ip;
                        inet_aton(new_ip.c_str(), &source);
                        incomingIpHdr->saddr = source.s_addr;
                    }
                    else {
                        // receiving from WAN; need to change to LAN
                        new_ip = napt_table[entry_ind].lan_ip;
                        inet_aton(new_ip.c_str(), &destination);
                        incomingIpHdr->daddr = destination.s_addr;
                    }
                    
                    // update port
                    int new_port = 0;
                    if (lanToWan) {
                        new_port = htons(napt_table[entry_ind].wan_port);
                        std::cout << "Translated source: (" << napt_table[entry_ind].lan_ip << ", " 
                                                            << napt_table[entry_ind].lan_port << ") -> ("
                                                            << inet_ntoa(source) << ", ";
                        if (incomingIpHdr->protocol == IPPROTO_TCP) {
                            incomingTcpHdr->th_sport = new_port;
                            std::cout << ntohs(incomingTcpHdr->th_sport) << ")" << std::endl;
                        }
                        else if (incomingIpHdr->protocol == IPPROTO_UDP) {
                            incomingUdpHdr->uh_sport = new_port;
                            std::cout << ntohs(incomingUdpHdr->uh_sport) << ")" << std::endl;
                        }
                    }
                    else {
                        new_port = htons(napt_table[entry_ind].lan_port);
                        std::cout << "Translated destination: (" << napt_table[entry_ind].wan_ip << ", " 
                                                                 << napt_table[entry_ind].wan_port << ") -> ("
                                                                 << inet_ntoa(destination) << ", ";
                        if (incomingIpHdr->protocol == IPPROTO_TCP) {
                            incomingTcpHdr->th_dport = new_port;
                            std::cout<< ntohs(incomingTcpHdr->th_dport) << ")" << std::endl;
                        }
                        else if (incomingIpHdr->protocol == IPPROTO_UDP) {
                            incomingUdpHdr->uh_dport = new_port;
                            std::cout<< ntohs(incomingUdpHdr->uh_dport) << ")" << std::endl;
                        }
                    }
                    
                    uint32_t pseudo_sum = 0;
                    pseudo_sum += (incomingIpHdr->saddr>>16) & 0xFFFF;
                    pseudo_sum += (incomingIpHdr->saddr) & 0xFFFF;
                    pseudo_sum += (incomingIpHdr->daddr>>16) & 0xFFFF;
                    pseudo_sum += (incomingIpHdr->daddr) & 0xFFFF;
                    
                    // checksum calculation
                    if (incomingIpHdr->protocol == IPPROTO_TCP) {
                        pseudo_sum += htons(IPPROTO_TCP); //TCP protocol num 6
                        pseudo_sum += htons(totLen - hdrLen); // tcp header + payload
                        incomingTcpHdr->th_sum = 0;
                        update_checksum(incomingTcpHdr->th_sum, totLen - hdrLen, pkt.data() + hdrLen, pseudo_sum);
                        std::cout << "tcpchecksum: " << incomingTcpHdr->th_sum << std::endl;
                    }
                    else if (incomingIpHdr->protocol == IPPROTO_UDP) {
                        pseudo_sum += htons(IPPROTO_UDP); //UDP protocol num 17
                        pseudo_sum += incomingUdpHdr->uh_ulen;
                        incomingUdpHdr->uh_sum = 0;
                        update_checksum(incomingUdpHdr->uh_sum, totLen - hdrLen, pkt.data() + hdrLen, pseudo_sum);
                        std::cout << "udpchecksum: " << incomingUdpHdr->uh_sum << std::endl;
                    }
                }

                /* // TCP or UDP protocol
                if (incomingIpHdr->protocol == IPPROTO_TCP) {
                    std::cout << "protocol: TCP" << std::endl;
                    auto tcpHdrLen = static_cast<size_t>(incomingTcpHdr->th_off) * 4;
                    // NAPT magic
                        // inet_ntoa(source) != "10.0.0.10" && inet_ntoa(destination) != "10.0.0.10"
                    // The server drops unrecognized packets sent from WAN. (5 pt)
                    
                    // wait this is kinda tricky. bc dest can not be LAN but still be in the NAPT table
                    // then should we handle it inside the else section where we actually loop through napt table
                    // probably yea
                    // oh btw we didn't end up doing this                   
                    
                    bool recognized = false;
                    for (int i = 0; i < tableEntryNum; i++) {
                        // LAN -> WAN
                        if (inet_ntoa(source) == napt_table[i].lan_ip){
                            //ipMatched = true;
                            if (ntohs(incomingTcpHdr->th_sport) == napt_table[i].lan_port) {
                                //portMatched = true;
                                lanToWan = true;
                                // sanity check
                                auto oldSourcePort = static_cast<size_t>(ntohs(incomingTcpHdr->th_sport));
                                // change the addresses
                                inet_aton(napt_table[i].wan_ip.c_str(), &source); // new addr is stored in source.s_addr
                                incomingIpHdr->saddr = source.s_addr;
                                // change the ports
                                incomingTcpHdr->th_sport = htons(napt_table[i].wan_port);
                                // check the outputs
                                
                                //TODO: FIX 
                                auto newSourcePort = static_cast<size_t>(ntohs(incomingTcpHdr->th_sport));
                                std::cout << "translate: previousAddr= " << inet_ntoa(source) << ", currentAddr= " << inet_ntoa(source) << std::endl;
                                std::cout << "translate: previousPort= " << oldSourcePort << ", currentPort= " << newSourcePort << std::endl;
                                //checksum calculation for tcp
                                uint32_t tcpsum = 0;
                                
                                incomingTcpHdr->th_sum = 0;
                                uint32_t i = 0;
                                for (; i < totLen - hdrLen - 1; i += 2) {
                                    auto headerword = reinterpret_cast<uint16_t*>(pkt.data() + hdrLen + i);
                                    tcpsum += *headerword;
                                    // sum += ntohs(*headerword);
                                }

                                // what is this checking for?? is it if the TCP segment is odd
                                // ohh so then can we just pull the for loop conditional and use that?
                                // it would be i + 1 == _____ tho right? ohhhhh no nvm yea bc if totLen-hdrLen = 25; then i would end up on 26 yes!
                                // the reason i pulled iterator variable out of loop was bc of this if statement
                                // so in the for loop above we increment by 2, and if the data is odd then we can't
                                // yeah i dont think i touched this code since we changed the condition so it's outdated
                                if ((totLen - hdrLen)%2){
                                    auto headerword = reinterpret_cast<uint16_t*>(pkt.data() + hdrLen + i ); //not sure about here; i think that makes sense
                                    tcpsum += (*headerword)&htons(0xFF00); // i think?? the rest should be fine let me run it
                                }
                                //add pseudo header
                                tcpsum += (incomingIpHdr->saddr>>16) & 0xFFFF;
                                tcpsum += (incomingIpHdr->saddr) & 0xFFFF;
                                tcpsum += (incomingIpHdr->daddr>>16) & 0xFFFF;
                                tcpsum += (incomingIpHdr->daddr) & 0xFFFF;
                                tcpsum += htons(IPPROTO_TCP); //TCP protocol num 
                                tcpsum += htons(totLen - hdrLen); //tcp header + payload
                                
                                while (tcpsum >> 16) {
                                    tcpsum = (tcpsum & 0xffff) + (tcpsum >> 16);
                                }
                                // one's complement
                                tcpsum = ~tcpsum;
                                incomingTcpHdr->th_sum = tcpsum;
                                cout << "tcpchecksum: " << incomingTcpHdr->th_sum << endl;
                                recognized = true;
                                break;
                            }
                        } 
                        // receiving from WAN; need to change to LAN
                        else if (inet_ntoa(destination) == napt_table[i].wan_ip && ntohs(incomingTcpHdr->th_dport) == napt_table[i].wan_port) {
                            // sanity check
                            auto oldDestPort = static_cast<size_t>(ntohs(incomingTcpHdr->th_dport));
                            // change the addresses
                            inet_aton(napt_table[i].lan_ip.c_str(), &destination);  // new addr is stored in destination.s_addr
                            incomingIpHdr->daddr = destination.s_addr;
                            // change the ports
                            incomingTcpHdr->th_dport = htons(napt_table[i].lan_port);
                            // check the outputs
                            //TODO: FIX
                            auto newDestPort = static_cast<size_t>(ntohs(incomingTcpHdr->th_dport));
                            std::cout << "translate: previousAddr= " << inet_ntoa(destination) << ", currentAddr= " << inet_ntoa(destination) << std::endl;
                            std::cout << "translate: previousPort= " << oldDestPort << ", currentPort= " << newDestPort << std::endl;
                            //checksum calculation for tcp
                            uint32_t tcpsum = 0;
                            
                            incomingTcpHdr->th_sum = 0;
                            uint32_t i = 0;
                            for (; i < totLen - hdrLen - 1; i += 2) {
                                auto headerword = reinterpret_cast<uint16_t*>(pkt.data() + hdrLen + i);
                                tcpsum += *headerword;
                                // sum += ntohs(*headerword);
                            }
                            if ((totLen - hdrLen)%2){
                                auto headerword = reinterpret_cast<uint16_t*>(pkt.data() + hdrLen + i ); //not sure about here; i think that makes sense
                                tcpsum += (*headerword)&htons(0xFF00); // i think?? the rest should be fine let me run it
                            }
                            
                            //add pseudo header
                            tcpsum += (incomingIpHdr->saddr>>16) & 0xFFFF;
                            tcpsum += (incomingIpHdr->saddr) & 0xFFFF;
                            tcpsum += (incomingIpHdr->daddr>>16) & 0xFFFF;
                            tcpsum += (incomingIpHdr->daddr) & 0xFFFF;
                            tcpsum += htons(IPPROTO_TCP); //TCP protocol num 
                            tcpsum += htons(totLen - hdrLen); //tcp header + payload
                            
                            while (tcpsum >> 16) {
                                tcpsum = (tcpsum & 0xffff) + (tcpsum >> 16);
                            }
                            // one's complement
                            tcpsum = ~tcpsum;
                            incomingTcpHdr->th_sum = tcpsum;
                            cout << "tcpchecksum: " << incomingTcpHdr->th_sum << endl;
                            recognized = true;
                            break;
                        }

                            
                    

                        //checksum calculation for TCP
                        // uint32_t tcpsum = 0;
                        // incomingTcpHdr->th_sum = 0;
                        // for (uint32_t i = 0; i < incomingTcpHdr->th_ulen; i += 2) {
                        //     auto headerword = reinterpret_cast<uint16_t*>(pkt.data() + hdrlen + i);
                        //     tcpsum += *headerword;
                        //     // sum += ntohs(*headerword);
                        // }
                        // while (tcpsum >> 16) {
                        //     tcpsum = (tcpsum & 0xffff) + (tcpsum >> 16);
                        // }
                        // // one's complement
                        // tcpsum = ~tcpsum;
                        // incomingTcpHdr->th_sum = tcpsum;
                    }
                    auto sourcePort = static_cast<size_t>(ntohs(incomingTcpHdr->th_sport));
                    auto destPort = static_cast<size_t>(ntohs(incomingTcpHdr->th_dport));
                    std::cout << "sourePort: "<< sourcePort << " destPort: "<< destPort << std::endl;
                  
                    std::cout << "payloadLen: "<< totLen - hdrLen - tcpHdrLen << std::endl;

                    if (!recognized){
                        break;
                    }
                }
                else if (incomingIpHdr->protocol == IPPROTO_UDP) {
                    std::cout << "protocol: UDP" << std::endl;
                    // NAPT magic
                    bool recognized = false;
                    if (inet_netof(source) == inet_netof(destination)) {
                        recognized = true;
                    }
                    else {
                        bool ipMatched = false;
                        bool portMatched = false;
                        
                        
                        for (int i = 0; i < tableEntryNum; i++){
                            if (inet_ntoa(source) == napt_table[i].lan_ip){
                                ipMatched = true;
                                if (ntohs(incomingUdpHdr->uh_sport) == napt_table[i].lan_port){
                                    portMatched = true;
                                }
                            }
                        }
                        if (!portMatched && (inet_netof(source) == inet_netof(lanIP))){
                            napt_entry entry;
                            entry.lan_ip = inet_ntoa(source);
                            entry.lan_port = ntohs(incomingUdpHdr->uh_sport);
                            entry.wan_ip = szWanIp;
                            entry.wan_port = DYNAMIC_PORT_START + dynamicEntrynum;
                            napt_table[tableEntryNum] = entry;
                            tableEntryNum++;
                            dynamicEntrynum++;
                            for (int i = 0; i < tableEntryNum; i++){
                                std::cout << "entry " << i << ": " << napt_table[i].lan_ip << " " << napt_table[i].wan_ip << " " << napt_table[i].lan_port << " " << napt_table[i].wan_port << std::endl;
                            }
                        }
                        for (int i = 0; i < tableEntryNum; i++) {
                            cout << "entering UDP for loop" << endl;
                            // sending from LAN; need to change to WAN
                            if (inet_ntoa(source) == napt_table[i].lan_ip){
                                //ipMatched = true;
                                if (ntohs(incomingUdpHdr->uh_sport) == napt_table[i].lan_port){
                                    //portMatched = true;
                                    // sanity check
                                    lanToWan = true;
                                    auto oldSourcePort = static_cast<size_t>(ntohs(incomingUdpHdr->uh_sport));
                                    // change the addresses
                                    inet_aton(napt_table[i].wan_ip.c_str(), &source); // new addr is stored in source.s_addr
                                    incomingIpHdr->saddr = source.s_addr;
                                    // change the ports
                                    incomingUdpHdr->uh_sport = htons(napt_table[i].wan_port);
                                    // check the outputs
                                    
                                    //TODO: FIX 
                                    auto newSourcePort = static_cast<size_t>(ntohs(incomingUdpHdr->uh_sport));
                                    std::cout << "translate: previousAddr= " << inet_ntoa(source) << ", currentAddr= " << inet_ntoa(source) << std::endl;
                                    std::cout << "translate: previousPort= " << oldSourcePort << ", currentPort= " << newSourcePort << std::endl;
                                    
                                    
                                    //checksum calculation for udp
                                    uint32_t udpsum = 0;
                                    incomingUdpHdr->uh_sum = 0;
                                    uint32_t i = 0;
                                    for (; i < totLen - hdrLen - 1; i += 2) {
                                        auto headerword = reinterpret_cast<uint16_t*>(pkt.data() + hdrLen + i);
                                        udpsum += *headerword;
                                        // sum += ntohs(*headerword);
                                    }
                                    if ((totLen - hdrLen)%2){
                                        auto headerword = reinterpret_cast<uint16_t*>(pkt.data() + hdrLen + i ); //not sure about here; i think that makes sense
                                        udpsum += (*headerword)&htons(0xFF00); // i think?? the rest should be fine let me run it
                                    }
                                    //add pseudo header
                                    udpsum += (incomingIpHdr->saddr>>16) & 0xFFFF;
                                    udpsum += (incomingIpHdr->saddr) & 0xFFFF;
                                    udpsum += (incomingIpHdr->daddr>>16) & 0xFFFF;
                                    udpsum += (incomingIpHdr->daddr) & 0xFFFF;
                                    udpsum += htons(IPPROTO_UDP); //UDP protocol num 17
                                    udpsum += incomingUdpHdr->uh_ulen;
                                    while (udpsum >> 16) {
                                        udpsum = (udpsum & 0xffff) + (udpsum >> 16);
                                    }
                                    // one's complement
                                    udpsum = ~udpsum;
                                    incomingUdpHdr->uh_sum = udpsum;
                                    cout << "udpchecksum: " << incomingUdpHdr->uh_sum << endl;
                                    recognized = true;
                                    break;
                                }
                            }
                            // receiving from WAN; need to change to LAN
                            else if (inet_ntoa(destination) == napt_table[i].wan_ip && ntohs(incomingUdpHdr->uh_dport) == napt_table[i].wan_port) {
                                // sanity check
                                auto oldDestPort = static_cast<size_t>(ntohs(incomingUdpHdr->uh_dport));
                                // change the addresses
                                inet_aton(napt_table[i].lan_ip.c_str(), &destination);  // new addr is stored in destination.s_addr
                                incomingIpHdr->daddr = destination.s_addr;
                                // change the ports
                                incomingUdpHdr->uh_dport = htons(napt_table[i].lan_port);
                                // check the outputs
                                //TODO: FIX
                                auto newDestPort = static_cast<size_t>(ntohs(incomingUdpHdr->uh_dport));
                                std::cout << "translate: previousAddr= " << inet_ntoa(destination) << ", currentAddr= " << inet_ntoa(destination) << std::endl;
                                std::cout << "translate: previousPort= " << oldDestPort << ", currentPort= " << newDestPort << std::endl;

                                 //checksum calculation for udp
                                uint32_t udpsum = 0;
                                incomingUdpHdr->uh_sum = 0;
                                uint32_t i = 0;
                                for (; i < totLen - hdrLen - 1; i += 2) {
                                    auto headerword = reinterpret_cast<uint16_t*>(pkt.data() + hdrLen + i);
                                    udpsum += *headerword;
                                    // sum += ntohs(*headerword);
                                    
                                    // is this for loop for the payload? mmm ok yea that makes sense
                                    // bc it increments by 2 so that's gonna be 2 bytes == 16 bits from start of header
                                    // so then now we need stuff in the psuedo header; i do think UDP length gets added twice
                                    //udpheader + payload 
                                }
                                if ((totLen - hdrLen)%2){
                                    auto headerword = reinterpret_cast<uint16_t*>(pkt.data() + hdrLen + i ); //not sure about here; i think that makes sense
                                    udpsum += (*headerword)&htons(0xFF00); // i think?? the rest should be fine let me run it
                                }
                                
                                udpsum += (incomingIpHdr->saddr>>16) & 0xFFFF;
                                udpsum += (incomingIpHdr->saddr) & 0xFFFF;
                                udpsum += (incomingIpHdr->daddr>>16) & 0xFFFF;
                                udpsum += (incomingIpHdr->daddr) & 0xFFFF;
                                udpsum += htons(IPPROTO_UDP); //UDP protocol num 17
                                udpsum += incomingUdpHdr->uh_ulen;
                                //when adding these four onto the previous checksum it's very small (6000s) compared to expected (55000s)
                                // might be bc of the source and dest addr. the 
                                // wait the checksum it is a 16 bit number? so us using uint32_t is wrong?
                                //ip checksum was also 16 bit but we used uint32?
                                //w/o pseudo header: 0x6b47
                                //w pseudo header: 0x021b
                                // hmm; what did it sum become this time?? ohh...same huh
                                //0x1b02 yeah

                                // on thing that is somewhat interesting is for UDP, the endian-ness is different. 02 1b --> 0x021b ohh; or wait was i always wrong abt that?
                                //either way w pseudo header the value is way smaller which i don't think it matters anyways it just needs to match


                                    // would carry-over be an issue?
                                    //if any bytes are left after that for loop?
                                    //below while loop should take care of carrier
                                // found a github: https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
                                while (udpsum >> 16) {
                                    udpsum = (udpsum & 0xffff) + (udpsum >> 16);
                                }
                                // one's complement
                                udpsum = ~udpsum;
                                incomingUdpHdr->uh_sum = udpsum;
                                cout << "udpchecksum: " << incomingUdpHdr->uh_sum << endl;
                                recognized = true;
                                break;
                            
                            }
                            
                        }
                        
                    }
                    auto sourcePort = static_cast<size_t>(ntohs(incomingUdpHdr->uh_sport));
                    auto destPort = static_cast<size_t>(ntohs(incomingUdpHdr->uh_dport));
                    std::cout << "sourcePort: "<< sourcePort << " destPort: "<< destPort << std::endl;
                    if (!recognized){
                        break;
                    }
                } */
                
                std::cout << "source address: " << inet_ntoa(source) << ", destination address: " << inet_ntoa(destination) << std::endl;

                // The checksum field is the 16 bit one's complement of the one's
                // complement sum of all 16 bit words in the header.  For purposes of
                // computing the checksum, the value of the checksum field is zero.
                
                incomingIpHdr->check = 0;
                update_checksum(incomingIpHdr->check, hdrLen, pkt.data());
                std::cout << "checksum (after): " << incomingIpHdr->check << std::endl;
                
                if (lanToWan) {
                    std::cout << "lanToWan is True" << std::endl;
                    inet_aton("0.0.0.0", &destination);
                }

                if (send(client_sockets[inet_ntoa(destination)], incomingIpHdr, hdrLen, 0) == -1) {
                    perror("send");
                    std::cout << "send got -1" << std::endl;
                    break;
                }
                
                if (incomingIpHdr->protocol == IPPROTO_UDP) {
                    if(send(client_sockets[inet_ntoa(destination)], incomingUdpHdr, pkt.size() - hdrLen, 0) == -1){
                        perror("send");
                        std::cout << "send got -1" << std::endl;
                        break;
                    }
                }
                else if (incomingIpHdr->protocol == IPPROTO_TCP) {
                    if(send(client_sockets[inet_ntoa(destination)], incomingTcpHdr, pkt.size() - hdrLen, 0) == -1){
                        perror("send");
                        std::cout << "send got -1" << std::endl;
                        break;
                    }
                }
            }
        }
    }
    return 0;
}

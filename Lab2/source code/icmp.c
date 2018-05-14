#include <errno.h>
#include <fcntl.h>           
#include <netdb.h>            // getaddrinfo()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>       
#include <netinet/in.h>       
#include <netinet/ip.h>       /* struct ip */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
#ifndef ICMP_ECHO_REPLY
#define ICMP_ECHO_REPLY 0
#endif

#define REQUEST_TIMEOUT  1000000
#define REQUEST_INTERVAL 1000000

#define TIMEVAL_TO_USEC(tv) (tv.tv_sec * 1000000L + tv.tv_usec)

struct icmp {
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint16_t icmp_cksum;
    uint16_t icmp_id;
    uint16_t icmp_seq;
};

struct ip_icmp {
    struct ip   ip;
    struct icmp icmp;
};

// Computes the checksum of a packet
uint16_t compute_checksum(void *buf, size_t size) {
    size_t i;
    uint64_t sum = 0;

    for (i = 0; i < size; i += 2) {
        sum += *(uint16_t *)buf;
        buf = (uint8_t *)buf + 2;
    }

    if (size - i > 0) {
        sum += *(uint8_t *)buf;
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

int main(int argc, char **argv) {
    char *host;
    int sockfd;
    int error;
    struct addrinfo addrinfo_hints;
    struct addrinfo *addrinfo_head;
    struct addrinfo *addrinfo;
    char addrstr[INET6_ADDRSTRLEN];
    struct timeval start_time;
    struct icmp request;
    struct icmp reply;
    struct ip_icmp reply_wrapped;
    uint16_t id = (uint16_t)getpid();
    uint16_t seq = 0;
    int bytes_transferred;

    if (argc < 2) {
        fprintf(stderr, "Usage: ping <host>\n");
        exit(EXIT_FAILURE);
    }

    host = argv[1];
    memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
    addrinfo_hints.ai_family = AF_INET;
    addrinfo_hints.ai_socktype = SOCK_RAW;
    addrinfo_hints.ai_protocol = IPPROTO_ICMP;

    error = getaddrinfo(host, NULL, &addrinfo_hints, &addrinfo_head);
    if (error != 0) {
        fprintf(stderr, "Error: getaddrinfo: %s\n", gai_strerror(error));
        exit(EXIT_FAILURE);
    }

    for (addrinfo = addrinfo_head;
         addrinfo != NULL;
         addrinfo = addrinfo->ai_next) { 
        sockfd = socket(addrinfo->ai_family,
                        addrinfo->ai_socktype,
                        addrinfo->ai_protocol);
        if (sockfd == -1) {
            fprintf(stderr, "Error: socket: %s\n", strerror(errno));
            continue;
        }

        /* Socket was successfully created. */
        break;
    }

    if (addrinfo == NULL) {
        fprintf(stderr, "Error: Could not connect to %s\n", host);
        exit(EXIT_FAILURE);
    }

    switch (addrinfo->ai_family) {
        case AF_INET:
            inet_ntop(AF_INET,
                      &((struct sockaddr_in *)addrinfo->ai_addr)->sin_addr,
                      addrstr,
                      sizeof(addrstr));
            break;
        case AF_INET6:
            inet_ntop(AF_INET6,
                      &((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_addr,
                      addrstr,
                      sizeof(addrstr));
            break;
        default:
            strncpy(addrstr, "<unknown address>", sizeof(addrstr));
    }

    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        fprintf(stderr, "Error: fcntl: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    for (seq = 0; ; seq++) {
        long delay = 0;

        memset(&request, 0, sizeof(request));
        request.icmp_type = ICMP_ECHO;
        request.icmp_code = 0;
        request.icmp_cksum = 0;
        request.icmp_id = htons(id);
        request.icmp_seq = htons(seq);
        request.icmp_cksum = compute_checksum(&request, sizeof(request));

        bytes_transferred = sendto(sockfd,
                                   &request,
                                   sizeof(request),
                                   0,
                                   addrinfo->ai_addr,
                                   addrinfo->ai_addrlen);
        if (bytes_transferred < 0) {
            fprintf(stderr, "Error: sendto: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        printf("Sent ICMP echo request to %s\n", addrstr);
        gettimeofday(&start_time, NULL);

        for (;;) {
            struct timeval cur_time;

            gettimeofday(&cur_time, NULL);
            delay = TIMEVAL_TO_USEC(cur_time) - TIMEVAL_TO_USEC(start_time);

            memset(&reply_wrapped, 0, sizeof(reply_wrapped));
            bytes_transferred = recvfrom(sockfd,
                                         &reply_wrapped,
                                         sizeof(reply_wrapped),
                                         0,
                                         NULL,
                                         NULL);
            if (bytes_transferred < 0) {
                if (errno != EAGAIN) {
                    fprintf(stderr, "Error: recvfrom: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
                }
                if (delay > REQUEST_TIMEOUT) {
                    printf("Request timed out\n");
                    break;
                }
            } else {
                uint16_t checksum;
                uint16_t expected_checksum;

                reply = reply_wrapped.icmp;
                reply.icmp_cksum = ntohs(reply.icmp_cksum);
                reply.icmp_id = ntohs(reply.icmp_id);
                reply.icmp_seq = ntohs(reply.icmp_seq);

                if (reply.icmp_type != ICMP_ECHO_REPLY || reply.icmp_id != id) {
                    continue;
                }

                checksum = reply.icmp_cksum;
                reply.icmp_cksum = 0;
                expected_checksum = compute_checksum(&reply, sizeof(reply));

                printf("Received ICMP reply from %s: seq=%d, time=%.3f ms",
                       addrstr,
                       reply.icmp_seq,
                       delay / 1000.0);

                if (checksum != expected_checksum) {
                    printf(" (checksum mismatch: %x != %x)\n",
                           checksum,
                           expected_checksum);
                } else {
                    printf("\n");
                }

                break;
            }
        }

        usleep(REQUEST_INTERVAL - delay);
    }
}

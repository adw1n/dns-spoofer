#pragma once
#include <cstdint>
#include <cstdlib>
#include <arpa/inet.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sstream>
#include <map>
#include <set>


struct DNSQuery{
    const char * name;
    uint16_t type;
    uint16_t class_;

    std::string to_bytes();
    std::string get_name();
};
struct DNSResponse{
    uint16_t name;
    uint16_t type;
    uint16_t class_;
    uint32_t time_to_live;
    uint16_t data_length;
    uint32_t address;

    std::string to_bytes();
    void calculate_name();
};

struct DnsSection{
    uint16_t transaction_ID;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer_PRs;
    uint16_t authority_PRs;
    uint16_t additional_PRs;
    std::vector<DNSQuery> queries;
    std::vector<DNSResponse> answers;

    std::string to_bytes();
};

struct DNSVictim{
    std::string ip;
    std::string spoofed_source_ip;
    std::map<std::string,std::string> sites;
};

class PcapError: public std::runtime_error
{
public:
    PcapError(const std::string& what_arg):
            std::runtime_error(what_arg){};
    PcapError( const char* what_arg ):
            std::runtime_error(what_arg){};
};


template<class T>
void write_bytes_to_stream(const T& t, std::ostringstream& oss){
    oss.write((char *) &t, sizeof(t));
}

uint32_t bytes_to_int(const char* bytes, ssize_t len);

DnsSection parse_dns_section(const char * bytes, ssize_t len);

uint16_t calculate_ipv4_checksum(const iphdr* ip_hdr);

void send_dns_response(DnsSection dns_section_response, std::string destination_ip, u_int16_t port);


DnsSection construct_dns_section_response(DnsSection query, const std::string& ip);


void stop_dns_spoofing();
/*
 * @param victims: map<VICTIM_IP, map<DNS_TO_SPOOF, IP_ADDR>>
 */
void run_dns_spoof(const std::string& interface,  std::vector<DNSVictim>* victims);

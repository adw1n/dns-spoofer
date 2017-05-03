#define BOOST_TEST_DYN_LINK
//g++  test.cpp dns.cpp  -o test -lboost_unit_test_framework -std=c++11 -lpcap
#include <cstdlib>
#include <cstdio>
#include "dns.hpp"

#define BOOST_TEST_MODULE DNSTests
#include <boost/test/unit_test.hpp>

#include <boost/test/included/unit_test.hpp>
#include <netinet/ip.h>

BOOST_AUTO_TEST_CASE( single_dns_query )
{
    /*
     * Dumped from wireshark:
     * 0000   c4 01 01 00 00 01 00 00 00 00 00 00 02 77 70 02  .............wp.
     * 0010   70 6c 00 00 01 00 01                             pl.....
    */
    const char * wp_pl_query = "\xc4\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\x77\x70\x02\x70\x6c\x00\x00\x01\x00\x01";
    auto section = parse_dns_section(wp_pl_query, 23);
    BOOST_CHECK_EQUAL( section.transaction_ID , 0xc401 );
    BOOST_CHECK_EQUAL( section.flags , 0x0100 );
    BOOST_CHECK_EQUAL( section.questions , 0x1 );
    BOOST_CHECK_EQUAL( section.answer_PRs , 0x0 );
    BOOST_CHECK_EQUAL( section.authority_PRs , 0x0 );
    BOOST_CHECK_EQUAL( section.additional_PRs , 0x0 );
    BOOST_CHECK(strcmp(section.queries[0].name, "\x02wp\x02pl")==0);
    BOOST_CHECK_EQUAL(section.queries[0].get_name(), std::string("wp.pl"));
    BOOST_CHECK_EQUAL(section.queries[0].type, 0x1);
    BOOST_CHECK_EQUAL(section.queries[0].class_, 0x1);
    BOOST_CHECK(section.answers.empty());
}


BOOST_AUTO_TEST_CASE( dns_query_to_bytes )
{
    const char* wp_pl_query = "\x02\x77\x70\x02\x70\x6c\x00";
    auto query = DNSQuery();
    query.name=wp_pl_query;
    auto bytes = query.get_name();
    std::string real_url = "wp.pl";
    BOOST_CHECK_EQUAL( bytes.size() , real_url.size() );
    BOOST_CHECK_EQUAL( bytes , real_url );


    const char* facebook_com="\x08\x66\x61\x63\x65\x62\x6f\x6f\x6b\x03\x63\x6f\x6d\x00";
    query.name=facebook_com;
    bytes=query.get_name();
    real_url = "facebook.com";
    BOOST_CHECK_EQUAL( bytes.size() , real_url.size() );
    BOOST_CHECK_EQUAL( bytes , real_url );

}

BOOST_AUTO_TEST_CASE( dns_query_response )
{
    /*
     * Dumped from wireshark:
     * 0000   c4 01 01 00 00 01 00 00 00 00 00 00 02 77 70 02  .............wp.
     * 0010   70 6c 00 00 01 00 01                             pl.....
    */
    const char * wp_pl_query = "\xc4\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\x77\x70\x02\x70\x6c\x00\x00\x01\x00\x01";
    auto dns_section_question = parse_dns_section(wp_pl_query, 23);
    std::string spoofed_ip="192.168.1.111";
    auto dns_section_response = construct_dns_section_response(dns_section_question,spoofed_ip);


    BOOST_CHECK_EQUAL( dns_section_response.transaction_ID , 0xc401 );
    BOOST_CHECK_EQUAL( dns_section_response.flags , 0x8180 );
    BOOST_CHECK_EQUAL( dns_section_response.questions , 0x1 );
    BOOST_CHECK_EQUAL( dns_section_response.answer_PRs , 0x1 );
    BOOST_CHECK_EQUAL( dns_section_response.authority_PRs , 0x0 );
    BOOST_CHECK_EQUAL( dns_section_response.additional_PRs , 0x0 );

    BOOST_CHECK_EQUAL( dns_section_response.queries.size() , 1 );
    BOOST_CHECK(strcmp(dns_section_response.queries[0].name, "\x02wp\02pl")==0);
    BOOST_CHECK_EQUAL(dns_section_response.queries[0].type, 0x1);
    BOOST_CHECK_EQUAL(dns_section_response.queries[0].class_, 0x1);

    BOOST_CHECK_EQUAL(dns_section_response.answers.size(), 1);
    BOOST_CHECK_EQUAL(dns_section_response.answers[0].name, 0xc00c);
    BOOST_CHECK_EQUAL(dns_section_response.answers[0].type, 0x1);
    BOOST_CHECK_EQUAL(dns_section_response.answers[0].class_, 0x1);
    BOOST_CHECK_GT(dns_section_response.answers[0].time_to_live,50);
    BOOST_CHECK_LT(dns_section_response.answers[0].time_to_live,100);
    int expected_address;
    inet_pton(AF_INET, spoofed_ip.c_str(), &expected_address);
    BOOST_CHECK_EQUAL(dns_section_response.answers[0].address, expected_address);

}

BOOST_AUTO_TEST_CASE( dns_query_response_to_bytes )
{
    /*
     * Dumped from wireshark:
     * 0000   c4 01 01 00 00 01 00 00 00 00 00 00 02 77 70 02  .............wp.
     * 0010   70 6c 00 00 01 00 01                             pl.....
    */
    std::string wp_pl_query("\xc4\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\x77\x70\x02\x70\x6c\x00\x00\x01\x00\x01" ,23);
    auto dns_section_question = parse_dns_section(wp_pl_query.c_str(), wp_pl_query.size());
    std::string spoofed_ip="192.168.1.111";
    auto dns_section_response = construct_dns_section_response(dns_section_question,spoofed_ip);

    /*
     * 0000   c4 01 81 80 00 01 00 01 00 00 00 00 02 77 70 02  .............wp.
     * 0010   70 6c 00 00 01 00 01 c0 0c 00 01 00 01 00 00 00  pl..............
     * 0020   41 00 04 d4 4d 62 09                             A...Mb.
     *
     * s="c4018180000100010000000002777002706c0000010001c00c00010001000000410004d44d6209"
     * print(len(s)/2, "".join(["\\x"+s[i:i+2] for i in range(0,len(s),2)]))
     */
    ssize_t expected_len=39;
    std::string expected("\xc4\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x02\x77\x70\x02\x70\x6c\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x41\x00\x04\xd4\x4d\x62\x09",
                         expected_len);

    expected[expected_len-4]=(char) 192;
    expected[expected_len-3]=(char) 168;
    expected[expected_len-2]=(char) 1;
    expected[expected_len-1]=(char) 111;

    auto calcualted_bytes=dns_section_response.to_bytes();
    BOOST_CHECK_EQUAL(calcualted_bytes.size(), expected.size());
    BOOST_CHECK_EQUAL(calcualted_bytes, expected);

}




BOOST_AUTO_TEST_CASE( DNSQuery_to_bytes )
{
    const char * name = "\x02wp\x02pl";
    auto dns_query = DNSQuery();
    dns_query.name=name;
    dns_query.type=0x325;
    dns_query.class_=0x0102;
    auto raw_bytes = dns_query.to_bytes();
    BOOST_CHECK_EQUAL(raw_bytes.size(), 7+2+2);
    BOOST_CHECK(strncmp(raw_bytes.substr(0,7).c_str(),name,strlen(name)+1)==0);
    BOOST_CHECK_EQUAL(raw_bytes[7], 0x03);
    BOOST_CHECK_EQUAL(raw_bytes[8], 0x25);
    BOOST_CHECK_EQUAL(raw_bytes[9], 0x01);
    BOOST_CHECK_EQUAL(raw_bytes[10], 0x02);
}

BOOST_AUTO_TEST_CASE( DNSResponse_to_bytes )
{
    auto dns_response = DNSResponse();
    dns_response.name=0xc00c;
    dns_response.type=0x325;
    dns_response.class_=0x0102;
    dns_response.time_to_live=0x41;
    dns_response.data_length=4;
    uint32_t expected_address;
    inet_pton(AF_INET, "200.201.202.203", &expected_address);
    dns_response.address=expected_address;
    auto raw_bytes = dns_response.to_bytes();
    BOOST_CHECK_EQUAL(raw_bytes.size(), 2+2+2+4+2+4);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[0], 0xc0);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[1], 0x0c);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[2], 0x03);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[3], 0x25);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[4], 0x01);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[5], 0x02);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[6], 0x00);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[7], 0x00);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[8], 0x00);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[9], 0x41);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[10], 0x00);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[11], 0x04);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[12], 200);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[13], 201);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[14], 202);
    BOOST_CHECK_EQUAL((uint8_t ) raw_bytes[15], 203);
}



BOOST_AUTO_TEST_CASE( test_checksum_calculation )
{
    // taken from the wikipedia example https://en.wikipedia.org/wiki/IPv4_header_checksum
    const char * ip_hdr="\x45\x00\x00\x73\x00\x00\x40\x00\x40\x11\xb8\x61\xc0\xa8\x00\x01\xc0\xa8\x00\xc7";

    BOOST_CHECK_EQUAL(calculate_ipv4_checksum((iphdr*) ip_hdr), 0xB861);
    const char * ip_hdr2="\x45\x00\x00\x73\x00\x00\x40\x00\x40\x11\x00\x00\xc0\xa8\x00\x01\xc0\xa8\x00\xc7";

    BOOST_CHECK_EQUAL(calculate_ipv4_checksum((iphdr*) ip_hdr2), 0xB861);
}

//g++ -Wall test.cpp  -o test -lboost_unit_test_framework -DCPP_TESTS
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE FirewallTests

#include <boost/test/unit_test.hpp>
#include <boost/test/included/unit_test.hpp>

#include "firewall_helpers.h"
BOOST_AUTO_TEST_CASE( test_count_characters_in_string )
{
    const char * sites = "wp.pl|facebook.com|google.com|youtube.com";
    BOOST_CHECK_EQUAL(count_characters_in_string(sites, '|'), 3);
}
BOOST_AUTO_TEST_CASE( test_strlen_to_dot )
{
    BOOST_CHECK_EQUAL(strlen_to_char("wp.pl", '.'), 2);
    BOOST_CHECK_EQUAL(strlen_to_char("pl", '.'), 2);
    BOOST_CHECK_EQUAL(strlen_to_char("facebook.com", '.'), 8);
    BOOST_CHECK_EQUAL(strlen_to_char("com", '.'), 3);
}
BOOST_AUTO_TEST_CASE( test_calculate_blocked_sites )
{

    const char * sites = "wp.pl|facebook.com|music.google.com|youtube.com";
    char** blocked_sites=NULL;
    size_t number_of_sites;
    BOOST_CHECK_EQUAL(calculate_blocked_sites(const_cast<char*>(sites), &blocked_sites, &number_of_sites), true);
    BOOST_CHECK_EQUAL(number_of_sites, 4);
    BOOST_CHECK(blocked_sites!=NULL);
    BOOST_CHECK_EQUAL(strncmp(blocked_sites[0], "\02wp\02pl",7),0);
    BOOST_CHECK_EQUAL(blocked_sites[1][0], 8);
    BOOST_CHECK_EQUAL(blocked_sites[1][9], 3);
    BOOST_CHECK_EQUAL(blocked_sites[1][10], 'c');
    BOOST_CHECK_EQUAL(strncmp(blocked_sites[1], "\u0008facebook\03com",10),0);
    BOOST_CHECK_EQUAL(strncmp(blocked_sites[2], "\05music\x06google\03com",13),0);
    BOOST_CHECK_EQUAL(strncmp(blocked_sites[2], "\05music\06google\03com",14),0);
    BOOST_CHECK_EQUAL(strncmp(blocked_sites[3], "\07youtube\03com",13),0);
    free_sites(&blocked_sites, number_of_sites);
    BOOST_CHECK(blocked_sites==NULL);
}


BOOST_AUTO_TEST_CASE( test_verify_dns_should_pass )
{
    const char * aa_pl_query = "\xc4\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\x61\x61\x02\x70\x6c\x00\x00\x01\x00\x01";
    const char * blocked_sites[]={"\02wp\02pl", "\07youtube\03com"};
    BOOST_CHECK_EQUAL(verify_dns(aa_pl_query,23 , (char**)(blocked_sites), 2), true);
}
BOOST_AUTO_TEST_CASE( test_verify_dns_should_block )
{
    const char * wp_pl_query = "\xc4\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\x77\x70\x02\x70\x6c\x00\x00\x01\x00\x01";
    const char * blocked_sites[]={"\02wp\02pl", "\07youtube\03com"};
    BOOST_CHECK_EQUAL(verify_dns(wp_pl_query,23 , (char**)(blocked_sites), 2), false);
}

BOOST_AUTO_TEST_CASE( test_verify_dns_multiple_questions_should_pass )
{
    const char * dns_query = "\xc4\x01\x01\x00\x00\03\x00\x00\x00\x00\x00\x00\x02\x77\x70\x02\x70\x6c\x00\x00\x01\x00\x01" //wp.pl
            "\x04\x70\x6c\x61\x79\x06\x67\x6f\x6f\x67\x6c\x65\03\x63\x6f\x6d\x00\x00\x01\x00\x01"//play.google.com
            "\u000d\x6e\x6f\x74\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x73\06\x67\x6f\x6f\x67\x6c\x65\03\x63\x6f\x6d\x00\x00\x1c\x00\x01"; //notifications.google.com
    const char * blocked_sites[]={"\02aa\02pl", "\07youtube\03com"};
    BOOST_CHECK_EQUAL(verify_dns(dns_query,23+21+30 , (char**)(blocked_sites), 2), true);
}

BOOST_AUTO_TEST_CASE( test_verify_dns_multiple_questions_should_block )
{
    const char * dns_query = "\xc4\x01\x01\x00\x00\03\x00\x00\x00\x00\x00\x00\x02\x77\x70\x02\x70\x6c\x00\x00\x01\x00\x01" //wp.pl
            "\x04\x70\x6c\x61\x79\x06\x67\x6f\x6f\x67\x6c\x65\03\x63\x6f\x6d\x00\x00\x01\x00\x01"//play.google.com
            "\u000d\x6e\x6f\x74\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x73\06\x67\x6f\x6f\x67\x6c\x65\03\x63\x6f\x6d\x00\x00\x1c\x00\x01"; //notifications.google.com
    const char * blocked_sites[]={"\04play\06google\03com", "\07youtube\03com"};
    BOOST_CHECK_EQUAL(verify_dns(dns_query,23+21+30 , (char**)(blocked_sites), 2), false);
}

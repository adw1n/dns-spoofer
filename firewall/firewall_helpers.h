#pragma once
#ifdef CPP_TESTS
    #define vmalloc malloc
    #define vfree free
    #define __constant_ntohs ntohs

    #import <cstdio>
    #include <cstring>
    #include <cstdlib>
    #include <iostream>
    #include <stdint.h>
    #include <netinet/in.h>
#else
    #include <linux/types.h>
    #include <linux/vmalloc.h>
#endif

static size_t strlen_to_char(const char * buf, char byte){
    int i;
    for(i=0;;++i)
        if(buf[i]==byte || buf[i]=='\x00') return i;
}
static size_t count_characters_in_string(const char* s, char byte){
    size_t len = strlen(s);
    size_t i;
    size_t res=0;
    for(i=0;i<len;++i)
        if(s[i]==byte) res++;
    return res;
}
static bool calculate_blocked_sites(char * sites_string, char *** blocked_sites, size_t * number_of_sites){
    *number_of_sites = count_characters_in_string(sites_string,'|')+1;
    *blocked_sites = (char**) vmalloc(*number_of_sites * sizeof(char *));
    if(*blocked_sites==NULL)
        return false;
    size_t site_no;
    int site_name_start_position=0;
    for(site_no=0; site_no<*number_of_sites; ++site_no){
        size_t site_len = strlen_to_char(sites_string+site_name_start_position, '|');
        char* site = (char*) vmalloc(site_len+1+1); //+1 for \x00 and +1 for the first digit
        (*blocked_sites)[site_no]=site;
        if(site==NULL)
            return false;
        strncpy(site+1, sites_string +site_name_start_position, site_len);
        site[0]=strlen_to_char(sites_string +site_name_start_position, '.');
        site_name_start_position+=site_len+1;
        site[site_len+1]='\x00';
        size_t i;
        for(i=1; i<site_len+1; i++){
            if(site[i]=='.') {
                site[i] = strlen_to_char(site + i + 1, '.');
            }
        }
    }
    return true;
}

static void free_sites(char*** blocked_sites, size_t number_of_sites){
    if(*blocked_sites==NULL) return;
    size_t site_no;
    for(site_no=0; site_no<number_of_sites; ++site_no){
        // free on NULL isn't a problem, but there is a risk that the data further down has uninitialized
        // pointers with meaningless values (no calloc)
        if((*blocked_sites)[site_no]==NULL)
            break;
        vfree((*blocked_sites)[site_no]);
    }
    vfree(*blocked_sites);
    *blocked_sites=NULL;
}


static bool verify_dns(const char* bytes, size_t len, char** blocked_sites, size_t number_of_sites){
    if(len<6)
        return true;
    // TODO consider checking answers > 0 to block only responses
    // although if you define the gateway's and victim's IPs ok this shouldn't matter
    uint16_t questions=__constant_ntohs(*((uint16_t*) (bytes+4)));
    if(len<13) //protect against malicious hand crafted "dns requests" that are not a dns request at all
        return true;
    const char * question_start_pointer = bytes+12;
    int question_number;
    for(question_number=0; question_number<questions && (question_start_pointer-bytes)<len; ++question_number){
        size_t question_length = strlen((char*)question_start_pointer)+1;
        if(question_start_pointer+question_length-bytes>=len)
            return true;
        size_t site_no;
        for(site_no=0;site_no<number_of_sites;++site_no){
            size_t site_len=strlen(blocked_sites[site_no])+1;
            if(site_len==question_length)
                if(strncmp(question_start_pointer, blocked_sites[site_no], question_length)==0)
                    return false;
        }
        question_start_pointer+=question_length+2+2;
    }

    return true;
}

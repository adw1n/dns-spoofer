from distutils.core import setup, Extension

dnsspoofer_module = Extension('dnsspoofer',
                    libraries = ['net', 'pcap'],
                    extra_compile_args=['-std=c++11'],
                    language='c++',
                    sources = ['dnsspoofer.cpp', 'dns.cpp'])

setup (name = 'dnsspoofer',
       version = '1.0',
       description = 'Spoof DNS and ARP like there is no tomorrow!',
       ext_modules = [dnsspoofer_module])

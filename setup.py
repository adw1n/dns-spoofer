from distutils.core import setup, Extension

module1 = Extension('dnsspoofer',
                    libraries = ['net'],
                    extra_compile_args=['-std=c++11'],
                    language='c++',
                    sources = ['dnsspoofer.cpp'])

setup (name = 'dnsspoofer',
       version = '1.0',
       description = 'Spoof like there is no tomorrow!',
       ext_modules = [module1])

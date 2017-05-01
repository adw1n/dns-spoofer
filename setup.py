from distutils.core import setup, Extension

module1 = Extension('dnsspoofer',
                    libraries = ['net'],
                    sources = ['dnsspoofer.c'])

setup (name = 'dnsspoofer',
       version = '1.0',
       description = 'Spoof like there is no tomorrow!',
       ext_modules = [module1])

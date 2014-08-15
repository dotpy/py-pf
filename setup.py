#!/usr/bin/env python

"""
This is the setup script of py-pf. You can install the module by running it with
the 'install' command:

    # python setup.py install

or run unit tests by calling it with the 'test' command:

    # python setup.py install
"""

from distutils.core import setup
from pf.tests import TestCommand


__author__ = "Daniele Mazzocchio <danix@kernel-panic.it>"
__version__ = "0.1.2"
__date__    = "May 27, 2014"


setup(name         = "py-pf",
      version      = __version__,
      author       = "Daniele Mazzocchio",
      author_email = "danix@kernel-panic.it",
      url          = "http://www.kernel-panic.it/software/py-pf/",
      download_url = "http://sourceforge.net/projects/py-pf/",
      packages     = ["pf", "pf.tests"],
      cmdclass     = {"test": TestCommand},
      license      = "OSI-Approved :: BSD License",
      description  = "Pure-Python module for managing OpenBSD's Packet Filter",
      classifiers  = ["Development Status :: 4 - Beta",
                      "Intended Audience :: System Administrators",
                      "License :: OSI Approved :: BSD License",
                      "Natural Language :: English",
                      "Operating System :: POSIX :: BSD :: OpenBSD",
                      "Programming Language :: Python",
                      "Topic :: System :: Networking :: Firewalls"])

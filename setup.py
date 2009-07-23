#!/usr/bin/env python

"""
This is the installation and setup script of the py-PF module, which allows you
to manage OpenBSD's Packet Filter from Python scripts. You can run it by typing
(as root):

  python setup.py install

in the directory you expanded the source into. This will copy the PF module in
the third-party modules directory, i.e. /usr/local/lib/python2.x/site-packages.
"""


import sys
from distutils.core import setup


__author__ = "Daniele Mazzocchio <danix@kernel-panic.it>"
__version__ = "0.0.4"
__date__    = "Jul 26, 2009"


# Python versions prior 2.2.3 don't support 'classifiers' and 'download_url'
if sys.version < "2.2.3":
    from distutils.dist import DistributionMetadata
    DistributionMetadata.classifiers = None
    DistributionMetadata.download_url = None

setup(name         = "py-PF",
      version      = __version__,
      author       = "Daniele Mazzocchio",
      author_email = "danix@kernel-panic.it",
      url          = "http://www.kernel-panic.it/software/py-pf/",
      download_url = "http://sourceforge.net/projects/py-pf/",
      packages     = ["PF"],
      requires     = ["ctypes"],
      license      = "OSI-Approved :: BSD License",
      description  = "Pure-Python module for managing OpenBSD's Packet Filter",
      classifiers  = ["Development status :: 2 - Pre-Alpha",
                      "Intended Audience :: System Administrators",
                      "License :: OSI-Approved Open Source :: BSD License",
                      "Natural Language :: English",
                      "Operating System :: OpenBSD",
                      "Programming Language :: Python",
                      "Topic :: Firewalls"])


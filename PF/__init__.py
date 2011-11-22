"""A package for managing OpenBSD's Packet Filter."""

__copyright__ = """
Copyright (c) 2008-2012, Daniele Mazzocchio
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

   * Redistributions of source code must retain the above copyright notice, this
     list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.
   * Neither the name of the developer nor the names of its contributors may be
     used to endorse or promote products derived from this software without
     specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


import os


__author__  = "Daniele Mazzocchio <danix@kernel-panic.it>"
__version__ = "0.0.7"


class PFError(Exception):
    """Base class for PF-related errors."""
    pass


from PFConstants import *
from PFStatus import *
from PFTable import *
from PFRule import *
from PFState import *
from PFAltq import *
from PacketFilter import *


__all__ = ['PFError',
           'PFStatus',
           'PFIface',
           'PFUid',
           'PFGid',
           'PFAddr',
           'PFPort',
           'PFRuleAddr',
           'PFPool',
           'PFRule',
           'PFRuleset',
           'PFStatePeer',
           'PFStateKey',
           'PFState',
           'PFTableAddr',
           'PFTable',
           'PFTStats',
           'PFAltqCBQ',
           'PFAltqHFSC',
           'PFAltqPriQ',
           'PacketFilter']

import PFConstants
__all__.extend(os._get_exports_list(PFConstants))
del PFConstants

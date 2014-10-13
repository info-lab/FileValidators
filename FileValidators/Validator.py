# CIRA File Validators
# Copyright (C) 2014 InFo-Lab
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU
# Lesser General Public License as published by the Free Software Foundation; either version 2 of
# the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not,
# write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

# coding=utf-8
from abc import ABCMeta


class Validator(object):
    """
    Abstract class that defines the Validator Interface.
    """
    __metaclass__ = ABCMeta

    def __init__(self):
        """
        Setting the behaviour for most validators. All validators are expected to have is_valid,
        eof, and bytes_last_valid attributes. Some methods rely on this variables.

        :var is_valid: tells if the last file that was validated was valid. (bool)
        :var eof: tells if the validator reached EOF in the last file that was validated. (bool)
        :var bytes_last_valid: tells the last offset within the file that was valid. (int)
        """
        self.is_valid = False
        self.eof = False
        self.bytes_last_valid = -1
        self.end = False
        self.fd = None

    def GetDetails(self):
        """
        Returns a dictionary with detailed validator-specific information about the last validated
        file. Its a mean to provide a single interface to get more information, which is format
        specific.

        :return: a dictionary of objects
        """
        return {}
        
    def GetStatus(self):
        """
        Returns the status of the validator after validating a file.

        :return: tuple of:
            * is_valid (bool)
            * eof (bool)
            * bytes_last_valid (int)
            * end (bool)
        """
        return self.is_valid, self.eof, self.bytes_last_valid, self.end
            
    def Validate(self, fd):
        """
        Validates a file-like object. Returns True or False. Further information can be obtained
        through GetStatus() or GetDetails().

        :param fd: a file-like object -- must support file methods: read, seek, tell, etc. Also,
            if its a file, it must be opened for binary reads.
        :return: True on a valid file, False otherwise.
        """
        pass

    def _Read(self, length):
        data = self.fd.read(length)
        if len(data) < length:
            self.eof = True
        return data

    def _CountValidBytes(self, bytes_read):
        """
        Makes internal accounting of valid bytes.

        :param bytes_read: the amount of valid bytes read in a previous read operation (int)
        """
        if self.is_valid and not self.eof:
            self.bytes_last_valid += bytes_read
            #print self.bytes_last_valid,

    def _SetValidBytes(self, value):
        """
        Sets the internal accounting of valid bytes. USE WITH CARE!

        :param value: the amount of valid bytes (int)
        """
        if self.is_valid:
            self.bytes_last_valid = value
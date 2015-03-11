# CIRA File Validators
# Copyright (C) 2014-2015 InFo-Lab
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

import datetime
import struct

from Validator import Validator


class NTFSFileRecordValidator(Validator):
    """
    Class that validates an object to determine if it is a valid NTFS FILE Record (from the MFT).

    Still in development, this Validator also focuses in extracting information from FILE records,
    so it can be used as a parser.
    """

    def __init__(self):
        """
        Calls Validator.__init__() and sets some internal attributes for the validation process.

        """
        super(NTFSFileRecordValidator, self).__init__()
        self.data = ""
        self.pos = 0
        self.details = {}
        self.magic = "L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F"

    def _ConvertBytes(self, value):
        pass

    def _Read(self, length):
        ret = self.data[self.pos: self.pos + length]
        if len(ret) < length:
            self.eof = True
        self.pos += length
        return ret

    def GetDetails(self):
        """
        Returns dictionary with important information from the recently-validated file.

        :return: dictionary {}
        """
        return self.details

    def _CleanDetails(self):
        self.details = {
            "extensions": [".filerecord"],
        }

    def Validate(self, fd):
        """
        Validates a file-like object to determine if its a valid NTFS FILE Record (from the MFT).

        :param fd: file-like object open for binary reading (file-like)
        :return: True on a valid FILE record, False otherwise (bool)
        """
        if type(fd) == file:
            self.data = fd.read()
        elif type(fd) == str:
            self.data = fd
        else:
            raise Exception("Argument must be either a file or a string.")
        # this first section has to change, for all validators
        self.pos = 0
        self.is_valid = True
        self.eof = False
        self.end = False
        self._SetValidBytes(0)
        self._CleanDetails()
        # and this top section could go to Validator, perhaps?
        # now we start with the header validation, this could go to a separate method, but it then
        # calling of

        return self.is_valid  # still working on the proper algorithm

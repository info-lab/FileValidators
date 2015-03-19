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

from collections import namedtuple
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
        # some structures to easy up everything later on
        self.st_header = struct.Struct("<4sHHQHHHHLLQH")
        self.nt_header = namedtuple("Header",
            "magic offset_update size_update lsn sequence_number hardlink_count offset_attribute "
            "flags size_real size_alloc base_record next_attribute")
        self.st_att_header = struct.Struct("<")
        self.attribute_types = {
            0x10: "$STANDARD_INFORMATION",
            0x20: "$ATTRIBUTE_LIST",
            0x30: "$FILE_NAME",
            0x40: "$OBJECT_ID",
            0x50: "$SECURITY_DESCRIPTOR",
            0x60: "$VOLUME_NAME",
            0x70: "$VOLUME_INFORMATION",
            0x80: "$DATA",
            0x90: "$INDEX_ROOT",
            0xa0: "$INDEX_ALLOCATION",
            0xb0: "$BITMAP",
            0xc0: "$REPARSE_POINT",
            0xd0: "$EA_INFORMATION",
            0xe0: "$EA",
            0xf0: "$PROPERTY_SET",
            0x100: "$LOGGED_UTILITY_STREAM",
        }

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

    def _MSTimestamp(self, timestamp):
        """
        Converts a MS Timestamp into a datetime object.
        :param timestamp: 64 bit MS timestap (string)
        :return:
        """
        tics, = struct.unpack("<Q", timestamp)
        days = tics / 864000000000
        rem = tics - days * 864000000000
        hours = rem / 36000000000
        rem -= hours * 36000000000
        minutes = rem / 600000000
        rem -= minutes * 600000000
        seconds = rem / 10000000
        rem -= seconds * 10000000
        microseconds = rem / 100
        td = datetime.timedelta(days)  # this way its easier to handle leap years
        date = datetime.datetime(1601, 1, 1, hours, minutes, seconds, microseconds) + td
        return date

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
        ############################################################################################
        data = self.data
        ############################################################################################
        # Parse the record header.
        # Parse the Attributes header
        # Parse each attribute type structures (STANDARD INFORMATION)
        # Interesting attributes for now: STANDARD_INFORMATION, FILENAME
        self.details["header"] = self.nt_header._make(self.st_header.unpack(data[0:42]))
        header = self.details["header"]
        self.is_valid = header.magic == "FILE" and header.size_alloc >= header.size_real
        if not self.is_valid:
            return False
        self.details["attributes"] = []
        attlist = self.details["attributes"]
        pos = header.offset_attribute
        att_type, att_len = struct.unpack("<LL", data[pos: pos + 8])
        while att_type in self.attribute_types:
            # print "Current: (%d, %d, %r) resident: %r" % \
            #      (att_type, att_len, struct.unpack("<L", data[pos + 0x10: pos + 0x14]),
            #      bool(struct.unpack("<B", data[pos + 0x08])[0]))
            attlist.append(self.attribute_types[att_type])
            # here we have to add the attribute header and attribute structures parsing code
            # for now, we just add the name of the attribute so we can test the code and see if
            # we're parsing the attribute list correctly.
            pos += att_len
            if pos + 8 <= len(data):
                att_type, att_len = struct.unpack("<LL", data[pos: pos + 8])
            elif pos + 4 <= len(data):
                att_type, att_len = struct.unpack("<L", data[pos: pos + 8])[0], 0
            else:
                att_type, att_len = -1, -1
            # print "Next: (%d, %d)" % (att_type, att_len)
        return self.is_valid  # still working on the proper algorithm

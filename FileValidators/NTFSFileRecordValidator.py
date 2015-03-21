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
        self.st_long = struct.Struct("<H")
        self.st_header = struct.Struct("<4sHHQHHHHLLQH")
        self.st_att_stdinfo = struct.Struct("<QQQQLLLLLLQQ")
        self.nt_header = namedtuple("Header",
            "magic offset_update size_update lsn sequence_number hardlink_count offset_attribute "
            "flags size_real size_alloc base_record next_attribute")
        self.nt_att_stdinfo = namedtuple("StandardInformation",
            "ctime atime mtime rtime fileperm maxver vernum classid ownerid secid quota usn")
        self.st_att_header = struct.Struct("<")
        self.attribute_types = {
            0x10: {"Type": "$STANDARD_INFORMATION", "Parsed": False},
            0x20: {"Type": "$ATTRIBUTE_LIST", "Parsed": False},
            0x30: {"Type": "$FILE_NAME", "Parsed": False},
            0x40: {"Type": "$OBJECT_ID", "Parsed": False},
            0x50: {"Type": "$SECURITY_DESCRIPTOR", "Parsed": False},
            0x60: {"Type": "$VOLUME_NAME", "Parsed": False},
            0x70: {"Type": "$VOLUME_INFORMATION", "Parsed": False},
            0x80: {"Type": "$DATA", "Parsed": False},
            0x90: {"Type": "$INDEX_ROOT", "Parsed": False},
            0xa0: {"Type": "$INDEX_ALLOCATION", "Parsed": False},
            0xb0: {"Type": "$BITMAP", "Parsed": False},
            0xc0: {"Type": "$REPARSE_POINT", "Parsed": False},
            0xd0: {"Type": "$EA_INFORMATION", "Parsed": False},
            0xe0: {"Type": "$EA", "Parsed": False},
            0xf0: {"Type": "$PROPERTY_SET", "Parsed": False},
            0x100: {"Type": "$LOGGED_UTILITY_STREAM", "Parsed": False},
        }
        self.attribute_parsers = {
            0x10: self._AttStdInfo,
        }

    def _AttStdInfo(self, att):
        """
        Parses a $STANDARD_INFORMATION attribute.

        :param att: attribute data, without the header.
        :return: dictionary with the attribute data.
        """
        values = self.nt_att_stdinfo._make(self.st_att_stdinfo.unpack(att[0:0x48]))
        ret = {
            "Type": "$STANDARD_INFORMATION",
            "Parsed": True,
            "CTime": self._MSTimestamp(values.ctime),
            "ATime": self._MSTimestamp(values.atime),
            "MTime": self._MSTimestamp(values.mtime),
            "RTime": self._MSTimestamp(values.rtime),
            "Permissions": {
                "ReadOnly": bool(values.fileperm & 0x0001),
                "Hidden": bool(values.fileperm & 0x0002),
                "System": bool(values.fileperm & 0x0004),
                "Archive": bool(values.fileperm & 0x0020),
                "Device": bool(values.fileperm & 0x0040),
                "Normal": bool(values.fileperm & 0x0080),
                "Temporary": bool(values.fileperm & 0x0100),
                "SparseFile": bool(values.fileperm & 0x0200),
                "ReparsePoint": bool(values.fileperm & 0x0400),
                "Compressed": bool(values.fileperm & 0x0800),
                "Offline": bool(values.fileperm & 0x1000),
                "NotContentIndexed": bool(values.fileperm & 0x2000),
                "Encrypted": bool(values.fileperm & 0x4000),
            },
            "MaxVersions": values.maxver,
            "VersionNumber": values.vernum,
            "ClassID": values.classid,
            "OwnerID": values.ownerid,
            "SecurityID": values.secid,
            "QuotaCharged": values.quota,
            "USN": values.usn,
        }
        return ret

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
        # tics, = struct.unpack("<Q", timestamp)
        tics = timestamp
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
            att_data = data[pos: pos + att_len]
            resident = att_data[0x08] == "\x00"
            if resident and att_type in self.attribute_parsers:
                att_offset, = self.st_long.unpack(att_data[0x14:0x16])
                parser = self.attribute_parsers[att_type]
                att = parser(att_data[att_offset:])
            else:
                att = self.attribute_types[att_type]
            attlist.append(att)
            # here we have to add the attribute header and attribute structures parsing code
            # for now, we just add the name of the attribute so we can test the code and see if
            # we're parsing the attribute list correctly.
            pos += att_len
            att_type, att_len = struct.unpack("<LL", data[pos: pos + 8])
            # print "Next: (%d, %d)" % (att_type, att_len)
        return self.is_valid  # still working on the proper algorithm

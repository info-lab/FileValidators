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

import datetime
import struct

from Validator import Validator


class LNKValidator(Validator):
    """
    Class that validates an object to determine if it is a valid MS-SHLLINK (LNK) file.
    """

    def __init__(self):
        """
        Calls Validator.__init__() and sets some internal attributes for the validation process.

        """
        super(LNKValidator, self).__init__()
        self.data = ""
        self.pos = 0
        self.details = {
            "item_list": [],
        }
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
        Returns dictionary with import information from the recently-validated file.

        :return: dictionary {}
        """
        return self.details

    def _CleanDetails(self):
        self.details = {
            "item_list": [],
        }

    def _IDList(self):
        """
        Internal method! Called from Validate when a IDList structure is present. It reads it and
        extracts data from it.
        """
        valid_delta = 2
        itemid_size, = struct.unpack("<H", self._Read(2))
        while itemid_size > 0:
            valid_delta += itemid_size + 2 # it may be counting an extra 2 bytes
            item = self._Read(itemid_size - 2)
            self.details["item_list"].append(item)
            itemid_size, = struct.unpack("<H", self._Read(2))
        print "ValidDelta(IDList): %d" % valid_delta
        self._CountValidBytes(valid_delta)

    def _LinkInfo(self):
        """
        Internal method! Called from Validate when a LinkInfo structure is present. It reads it and
        extracts data from it.
        """
        sizes_raw = self._Read(8)
        lnkinfo_size, lnkinfo_header_size = struct.unpack("<LL", sizes_raw)
        self.details["linkinfo"] = sizes_raw + self._Read(lnkinfo_size - 8)
        self.details["linkinfo_header"] = self.details["linkinfo"][:lnkinfo_header_size]
        # add checks for the LinkInfoHeader
        print "ValidDelta(LinkInfo): %d" % lnkinfo_size
        self._CountValidBytes(lnkinfo_size)

    def _Strings(self, string_flags, is_unicode):
        """
        Internal method! Called from Validate when a Strings section is present. Reads and extracts
        the strings from it.

        :param string_flags: a list of boolean values that tell which string is present in the
            structure (list of bool).
        """
        string_names = [
            "Name",
            "RelativePath",
            "WorkingDir",
            "Arguments",
            "IconLocation",
        ]
        ret = {}
        valid_delta = 0
        size_mult = 1
        if is_unicode:
            size_mult = 2
        for index, value in enumerate(string_flags):
            if value:
                size, = struct.unpack("<H", self._Read(2))
                size *= size_mult
                string = self._Read(size)
                if is_unicode:
                    string = string.decode("utf16")
                name = string_names[index]
                ret[name] = string
                valid_delta += 2 + size
        self._CountValidBytes(valid_delta)
        print "ValidDelta(Strings): %d" % valid_delta
        self.details["Strings"] = ret

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
        Validates a file-like object to determine if its a valid MS-SHLLINK (LNK) file .

        :param fd: file-like object open for binary reading (file-like)
        :return: True on a valid LNK file, False otherwise (bool)
        """
        if type(fd) == file:
            self.data = fd.read()
        elif type(fd) == str:
            self.data = fd
        else:
            raise Exception("Argument must be either a file or a string.")
        self.pos = 0
        self.is_valid = True
        self.eof = False
        self.end = False
        self._SetValidBytes(0)
        self._CleanDetails()
        shlheader = self._Read(76)
        magic_header = shlheader[0:20]
        flags_raw, fileatt_raw = struct.unpack("<LL", shlheader[20:28])
        self.details["ATime"] = self._MSTimestamp(shlheader[28:36])
        self.details["CTime"] = self._MSTimestamp(shlheader[36:44])
        self.details["WTime"] = self._MSTimestamp(shlheader[44:52])
        fsize, icoindex, shwcmd, hotkey = struct.unpack("<LLL2s", shlheader[52:66])
        reserve1, reserve2, reserve3 = struct.unpack("<HLL", shlheader[66:76])
        self.details["FileSize"] = fsize
        self.details["IconIndex"] = icoindex
        self.details["ShowCommand"] = shwcmd
        self.details["Hotkey"] = hotkey
        self.details["Reserved1"] = reserve1
        self.details["Reserved2"] = reserve2
        self.details["Reserved3"] = reserve3
        flags = {
            "HasLinkTargetIDList": bool(flags_raw & 0x00000001),
            "HasLinkInfo": bool(flags_raw & 0x00000002),
            "HasName": bool(flags_raw & 0x00000004),
            "HasRelativePath": bool(flags_raw & 0x00000008),
            "HasWorkingDir": bool(flags_raw & 0x00000010),
            "HasArguments": bool(flags_raw & 0x00000020),
            "HasIconLocation": bool(flags_raw & 0x00000040),
            "IsUnicode": bool(flags_raw & 0x00000080),
            "ForceNoLinkInfo": bool(flags_raw & 0x00000100),
            "HasExpString": bool(flags_raw & 0x00000200),
            "RunInSeparateProcess": bool(flags_raw & 0x00000400),
            "UNUSED1": bool(flags_raw & 0x00000800),
            "HasDarwinID": bool(flags_raw & 0x00001000),
            "RunAsUser": bool(flags_raw & 0x00002000),
            "HasExpIcon": bool(flags_raw & 0x00004000),
            "NoPidlAlias": bool(flags_raw & 0x00008000),
            "UNUSED2": bool(flags_raw & 0x00010000),
            "RunWithShimLayer": bool(flags_raw & 0x00020000),
            "ForceNoLinkTrack": bool(flags_raw & 0x00040000),
            "EnableTargetMetadata": bool(flags_raw & 0x00080000),
            "DisableLinkPathTracking": bool(flags_raw & 0x00100000),
            "DisableKnownFolderTracking": bool(flags_raw & 0x00200000),
            "DisableKnownFolderAlias": bool(flags_raw & 0x00400000),
            "AllowLinkToLink": bool(flags_raw & 0x00800000),
            "UnaliasOnSave": bool(flags_raw & 0x01000000),
            "PreferEnvironmentPath": bool(flags_raw & 0x02000000),
            "KeepLocalIDListForUNCTarget": bool(flags_raw & 0x04000000),
        }
        self.details["Flags"] = flags
        self.details["FileAttributes"] = {
            "ReadOnly": bool(fileatt_raw & 0x0001),
            "Hidden": bool(fileatt_raw & 0x0002),
            "System": bool(fileatt_raw & 0x0004),
            "RESERVED1": bool(fileatt_raw & 0x0008),
            "Directory": bool(fileatt_raw & 0x0010),
            "Archive": bool(fileatt_raw & 0x0020),
            "RESERVED2": bool(fileatt_raw & 0x0040),
            "Normal": bool(fileatt_raw & 0x0080),
            "Temporary": bool(fileatt_raw & 0x0100),
            "Sparse": bool(fileatt_raw & 0x0200),
            "ReparsePoint": bool(fileatt_raw & 0x0400),
            "Compressed": bool(fileatt_raw & 0x0800),
            "Offline": bool(fileatt_raw & 0x1000),
            "NotContentIndexed": bool(fileatt_raw & 0x2000),
            "Encrypted": bool(fileatt_raw & 0x4000),
        }
        hks = struct.unpack("<BB", hotkey)
        self.is_valid = (  # this way we can comment each line :)
            magic_header == self.magic and
            fileatt_raw < 32768 and
            shwcmd in {0x01, 0x03, 0x07} and  # might be a bit too strict
            (hks == (0, 0) or (0x30 <= hks[0] <= 0x91 and hks[1] in {1, 2, 4})) and
            reserve1 == 0 and
            reserve2 == 0 and
            reserve3 == 0
        )
            #(hotkey == "\x00\00" or (0x30 <= ord(hotkey[0]) <= 0x91 and \
            #    hotkey[1] in {"\x01", "\x02", "\x04"}))
        self._CountValidBytes(76)
        print "ValidBytes(LinkHeader): %d" % self.bytes_last_valid
        if flags["HasLinkTargetIDList"]:
            self._IDList()
        if flags["HasLinkInfo"]:
            self._LinkInfo()
        string_flags = [
            flags["HasName"],
            flags["HasRelativePath"],
            flags["HasWorkingDir"],
            flags["HasArguments"],
            flags["HasIconLocation"],
        ]
        if any(string_flags):
            self._Strings(string_flags, flags["IsUnicode"])
        return self.is_valid  # still working on the proper algorithm
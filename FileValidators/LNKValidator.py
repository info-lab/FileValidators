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

    Still in development, this Validator also focuses in extracting information from LNK Files, as
    such it can be used as a parser.
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
        Returns dictionary with important information from the recently-validated file.

        :return: dictionary {}
        """
        return self.details

    def _CleanDetails(self):
        self.details = {
            "extensions": [".lnk"],
        }

    def _ExtraData(self):
        """
        Internal method! Called from Validate to test if there's an ExtraData structure present. It
        reads it and extracts data from it.
        """
        block_methods = {
            "\x02\x00\x00\xa0": self._ExtraConsole,
            "\x04\x00\x00\xa0": self._ExtraConsoleFe,
            "\x06\x00\x00\xa0": self._ExtraDarwin,
            "\x01\x00\x00\xa0": self._ExtraEnvironment,
            "\x07\x00\x00\xa0": self._ExtraIcon,
            "\x0b\x00\x00\xa0": self._ExtraKnownFolder,
            "\x09\x00\x00\xa0": self._ExtraProperty,
            "\x08\x00\x00\xa0": self._ExtraShim,
            "\x05\x00\x00\xa0": self._ExtraSpecialFolder,
            "\x03\x00\x00\xa0": self._ExtraTracker,
            "\x0c\x00\x00\xa0": self._ExtraVista,
        }  # "jump-dictionary", probably the sanest way to parse the ExtraData block.
        tmp = []
        edl = 0
        size_raw = self._Read(4)
        if len(size_raw) == 4:
            edl = 4
            block_size, = struct.unpack("<L", size_raw)
            while block_size > 0:
                extra_data = size_raw + self._Read(block_size - 4)
                block_sign = extra_data[4:8]
                op = block_methods[block_sign]
                edl += len(extra_data)
                extra_data = op(extra_data)
                tmp.append(extra_data)
                size_raw = self._Read(4)
                block_size, = struct.unpack("<L", size_raw)
        # The problem with ExtraData is that it is a list of ExtraDataBlocks at the end of the file,
        # which is entirely optional and can be cut off from it. It has its own structure, so we
        # parse it and store it apart from the MS-SHLLINK structure.
        # Final length of the file is the valid bytes + extra data length.
        self.details["ExtraData"] = tmp
        self.details["ExtraDataLength"] = edl

    def _ExtraConsole(self, block):
        bsize, bsign, fillat, popatt, scrnbuffx, scrnbuffy = struct.unpack("<LLHHHH", block[0:16])
        winsizx, winsizy, winorigx, winorigy, u1, u2 = struct.unpack("<HHHHLL", block[16:32])
        fontsiz, fontfam, fontwgt, facename, cursiz = struct.unpack("<LLL64sL", block[32:112])
        fullscrn, quicked, insertm, autopos, histbuff = struct.unpack("<LLLLL", block[112:132])
        numhists, histnodup, coltable = struct.unpack("<LL64s", block[132:204])
        facename = facename.decode("utf-16")
        facename = facename[:facename.find("\x00")]
        coltable = [coltable[x * 4:x * 4 + 4] for x in xrange(16)]
        coltable = [struct.unpack("<BBBB", c) for c in coltable]
        return {
            "BlockType": "ConsoleDataBlock",
            "BlockSize": bsize,
            "BlockSignature": bsign,
            "FillAttributes": fillat,
            "PopupFillAttributes": popatt,
            "ScreenBufferSizeX": scrnbuffx,
            "ScreenBufferSizeY": scrnbuffy,
            "WindowsSizeX": winsizx,
            "WindowsSizeY": winsizy,
            "WindowsOriginX": winorigx,
            "WindowsOriginY": winorigy,
            "Unused1": u1,
            "Unused2": u2,
            "FontSize": fontsiz,
            "FontFamily": fontfam,
            "FontWeight": fontwgt,
            "FaceName": facename,
            "CursorSize": cursiz,
            "FullScreen": fullscrn,
            "QuickEdit": quicked,
            "InsertMode": insertm,
            "AutoPosition": autopos,
            "HistoryBufferSize": histbuff,
            "NumberOfHistoriyBuffers": numhists,
            "HistoryNoDup": histnodup,
            "ColorTable": coltable,
            #"DEBUG_RAW": block
        }

    def _ExtraConsoleFe(self, block):
        bsize, bsign, codepage = struct.unpack("<LLL", block[0:12])
        # slice used in case a bad block gets parsed by this method.
        return {
            "BlockType": "ConsoleFEDataBlock",
            "BlockSize": bsize,
            "BlockSignature": bsign,
            "CodePage": codepage,
            #"DEBUG_RAW": block
        }

    def _ExtraDarwin(self, block):
        bsize, bsign = struct.unpack("<LL", block[0:8])
        data_ansi = block[8:268]
        data_ansi = data_ansi[data_ansi.find("\x00")]
        data_unicode = block[268:788]
        data_unicode = data_unicode.decode("utf-16")
        data_unicode = data_unicode[data_unicode.find("\x00")]
        return {
            "BlockType": "DarwinDataBlock",
            "BlockSize": bsize,
            "BlockSignature": bsign,
            "DarwinDataAnsi": data_ansi,
            "DarwinDataUnicode": data_unicode,
            #"DEBUG_RAW": block
        }

    def _ExtraEnvironment(self, block):
        bsize, bsign = struct.unpack("<LL", block[0:8])
        data_ansi = block[8:268]
        data_ansi = data_ansi[data_ansi.find("\x00")]
        data_unicode = block[268:788]
        data_unicode = data_unicode.decode("utf-16")
        data_unicode = data_unicode[data_unicode.find("\x00")]
        return {
            "BlockType": "EnvironmentVariableDataBlock",
            "BlockSize": bsize,
            "BlockSignature": bsign,
            "TargetAnsi": data_ansi,
            "TargetUnicode": data_unicode,
            #"DEBUG_RAW": block
        }

    def _ExtraIcon(self, block):
        bsize, bsign = struct.unpack("<LL", block[0:8])
        data_ansi = block[8:268]
        data_ansi = data_ansi[data_ansi.find("\x00")]
        data_unicode = block[268:788]
        data_unicode = data_unicode.decode("utf-16")
        data_unicode = data_unicode[data_unicode.find("\x00")]
        return {
            "BlockType": "IconEnvironmentDataBlock",
            "BlockSize": bsize,
            "BlockSignature": bsign,
            "TargetAnsi": data_ansi,
            "TargetUnicode": data_unicode,
            #"DEBUG_RAW": block
        }

    def _ExtraKnownFolder(self, block):
        bsize, bsign, folderid, offset = struct.unpack("<LL16sL", block[0:36])
        return {
            "BlockType": "KnownFolderDataBlock",
            "BlockSize": bsize,
            "BlockSignature": bsign,
            "KnownFolderID": folderid,  # should parse folderid...
            "Offset": offset,
            #"DEBUG_RAW": block
        }

    def _ExtraProperty(self, block):
        bsize, bsign = struct.unpack("<LL", block[0:8])
        prop_store = block[8:]  # should parse this structure...
        return {
            "BlockType": "PropertyStoreDataBlock",
            "BlockSize": bsize,
            "BlockSignature": bsign,
            "PropertyStore": prop_store,
            #"DEBUG_RAW": block
        }

    def _ExtraShim(self, block):
        return {"DEBUG_RAW": block}

    def _ExtraSpecialFolder(self, block):
        return {"DEBUG_RAW": block}

    def _ExtraTracker(self, block):
        return {"DEBUG_RAW": block}

    def _ExtraVista(self, block):
        return {"DEBUG_RAW": block}

    def _IDList(self):
        """
        Internal method! Called from Validate when a IDList structure is present. It reads it and
        extracts data from it.
        """
        valid_delta = 2
        itemid_size, = struct.unpack("<H", self._Read(2))
        while itemid_size > 0:
            valid_delta += itemid_size
            item = self._Read(itemid_size - 2)
            self.details["item_list"].append(item)
            itemid_size, = struct.unpack("<H", self._Read(2))
        self._CountValidBytes(valid_delta)

    def _LinkInfo(self):
        """
        Internal method! Called from Validate when a LinkInfo structure is present. It reads it and
        extracts data from it.

        LinkInfo is a very complex structure, this method might need to be split into sub-methods.
        """
        tmp = {}
        sizes_raw = self._Read(8)
        linkinfo_size, linkinfo_header_size = struct.unpack("<LL", sizes_raw)
        linkinfo = sizes_raw + self._Read(linkinfo_size - 8)
        linkinfo_header = linkinfo[:linkinfo_header_size]
        # add checks for the LinkInfoHeader
        lbpath_offsetu, cps_offsetu = -1, -1
        flagsr, vid_offset, lbpath_offset, cnrl_offset = struct.unpack("<LLLL", linkinfo[8:24])
        cps_offset, = struct.unpack("<L", linkinfo[24:28])
        if linkinfo_header_size > 0x24:
            lbpath_offsetu, cps_offsetu = struct.unpack("<LL", linkinfo[28:36])
        flags = {
            "VolumeID": bool(flagsr & 0x00000001),
            "CommonNetwork": bool(flagsr & 0x00000002),
        }
        commonpath = linkinfo[cps_offset:]
        commonpath = commonpath[:commonpath.find("\x00")]
        tmp["CommonPathSuffix"] = commonpath
        if cps_offsetu > 0:
            commonpath_unicode = linkinfo[cps_offsetu]
            commonpath_unicode = commonpath_unicode.decode("utf-16")
            commonpath_unicode = commonpath_unicode[:commonpath_unicode.find("\x00")]
            tmp["CommonPathSuffixUnicode"] = commonpath_unicode
        if flags["VolumeID"]:  # and Local Base Path
            # we have to parse the VolumeID Structure
            rawvid = linkinfo[vid_offset:]
            vid_size, dtype, dserial, label_offset = struct.unpack("<LLLL", rawvid[0:16])
            volumeid = {
                "VolumeIDSize": vid_size,
                "DriveType": dtype,
                "DriveSerialNumber": dserial,
                "VolumeLabelOffset": label_offset,
            }
            rawvid = rawvid[:vid_size]  # no entirely necessary
            is_unicode = False
            if label_offset == 0x00000014:
                is_unicode = True
                label_offset = struct.unpack("<L", rawvid[16:20])
                volumeid["VolumeLabelOffsetUnicode"] = label_offset
            data = rawvid[label_offset:]
            if is_unicode:
                data = data.decode("utf-16")
            data = data[:-1]  # the strings are NULL terminated, always
            volumeid["Data"] = data
            # that's all for the VolumeID Structure, now to the LocalBasePath
            lb_unicode = False
            if lbpath_offsetu > -1:
                lb_offset = lbpath_offsetu
                lb_unicode = True
            else:
                lb_offset = lbpath_offset
            localbasepath = linkinfo[lb_offset:]
            if lb_unicode:
                localbasepath.decode("utf-16")
            localbasepath = localbasepath[:localbasepath.find("\x00")]
            # done parsing, now some checks
            # only valid drive types defined
            self.is_valid = self.is_valid and dtype in {0, 1, 2, 3, 4, 5, 6}
            # should add checks for the offsets
            # and now we add to the dictionary
            tmp["VolumeID"] = volumeid
            tmp["LocalBasePath"] = localbasepath
        if flags["CommonNetwork"]:
            # we have to parse the Common Network Relative Link Structure
            rawcnrl = linkinfo[vid_offset:]
            size, cnrl_flagsr, nn_offset, dn_offset, nptype = struct.unpack("<LLLLL", rawcnrl[0:20])
            rawcnrl = rawcnrl[:size]  # unnecessary
            cnrl_unicode = nn_offset > 0x14 and size > 0x1C
            nn_offset_u, dn_offset_u = -1, -1
            if cnrl_unicode:
                # we have optional fields in the CNRL header
                nn_offset_u, dn_offset_u = struct.unpack("<LL", rawcnrl[20:28])
            cnrl_flags = {
                "ValidDevice": bool(cnrl_flagsr & 0x00000001),
                "ValidNetType": bool(cnrl_flagsr & 0x00000002),
            }
            netname = rawcnrl[nn_offset:]
            netname = netname[:netname.find("\x00")]
            devicename = ""
            if cnrl_flags["ValidDevice"]:
                devicename = rawcnrl[dn_offset:]
                devicename = devicename[:devicename.find("\x00")]
            cnrl = {
                "CommonNetworkRelativeLinkSize": size,
                "CommonNetworkRelativeLinkFlags": cnrl_flags,
                "NetNameOffset": nn_offset,
                "DeviceNameOffset": dn_offset,
                "NetworkProviderType": nptype,  # maybe translate to a vendor name?
                "NetName": netname,
                "DeviceName": devicename,
                #"DEBUG_RAW": rawcnrl,
            }
            if cnrl_unicode:
                netnameu = rawcnrl[nn_offset_u:]
                netnameu = netnameu.decode("utf-16")
                netnameu = netnameu[:netnameu.find("\x00")]
                devicenameu = rawcnrl[dn_offset_u:]
                devicenameu = devicenameu.decode("utf-16")
                devicenameu = devicenameu[:devicenameu.find("\x00")]
                cnrl["NetNameOffsetUnicode"] = nn_offset_u
                cnrl["NetNameUnicode"] = netnameu
                cnrl["DeviceNameUnicode"] = devicenameu
                cnrl["DeviceOffsetUnicode"] = dn_offset_u
            tmp["CommonNetworkRelativeLink"] = cnrl
        # have to add some checks for the whole structure
        self.is_valid = (
            self.is_valid and
            flagsr < 4 and  # only active bits are b0 and b1, the rest should always be 0.
            True  # dummy value, will get removed later
        )
        self.details["LinkInfo"] = tmp
        self._CountValidBytes(linkinfo_size)

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
        ]  # this might be moved to an attribute
        tmp = {}
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
                tmp[name] = string
                valid_delta += 2 + size
        self._CountValidBytes(valid_delta)
        self.details["Strings"] = tmp

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
        self._ExtraData()
        return self.is_valid  # still working on the proper algorithm
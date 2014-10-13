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
import struct
import zlib

from Validator import Validator


class PNGValidator(Validator):
    """
    Class that validates an object to determine if it is a valid PNG file.
    """

    def __init__(self):
        """
        Calls Validator.__init__() and sets some internal attributes for the validation process.

        :var max_chunk_length: imposes a limit on segment length. Usually a too long segment is
            a sign of a corrupt file. Default is 20 MiB. (int)
        :var converters: dictionary of structs to unpack values to ints. (dict of struct.Struct)
        :var valid_chunks_list: a list contains 3 sub lists, each filled with the expected valid
            chunks for the part of the file that is being analyzed. First list is what is expected
            on a newly opened file (IHDR), second list is what is expect mid file, third list is
            empty and is what you expect after finding IEND segment.
        """
        super(PNGValidator, self).__init__()
        self.max_chunk_length = (1024 * 1024) * 40  # when the validators are used as workers for
        # a file structure based carver, this can lead to (very) bad behaviour, so we define a
        # maximum length for a valid PNG. Not entirely standard, but most surely a PNG reporting
        # chunk lengths of a few GiB is a corrupt PNG.
        # 40 MiB should cover *most* cases, but it can be adjusted.
        self.converters = {
            "uL":struct.Struct(">L"),  # unsigned long
            "sL":struct.Struct(">l"),  # signed long
        }
        self.valid_chunks_list = [
                ["IHDR"],
                ["PLTE", "IDAT", "IEND", "bKGD", "cHRM", "gAMA", "hIST", "iCCP", "iTXt", "pHYs",
                 "sBIT", "sPLT", "sRGB", "sTER", "tEXt", "tIME", "tRNS", "zTXt"],
                []
            ]
        # Append more segment descriptors to valid_chunk_list[1] if you need some special,
        # non-standard PNG to validate.
        self.segments = []

    def _ConvertBytes(self, value, t):
        """
        Converts packed bytes to int, either unsigned long (t="uL") for PNG chunk lengths or signed
        longs (t="sL") for CRC-32 checksums.

        :param value: packed binary value (string)
        :param t: type, either "uL" or "sL" (string)
        :return: unpacked value (int)
        """
        return self.converters[t].unpack(value)[0]

    def GetDetails(self):
        """
        Returns dictionary with import information from the recently-validated file.

        :return: dictionary {
            'segments': a list of tuples of the following format:
                (segid (string), offset (int), length (int), CRC-32 (long), CRC-32 calc (long))
                Segment segid is found at offset bytes in the file, takes up length bytes (count
                from the segid offset including the CRC-32 and the calculated CRC-32)
        }
        """
        return {
            'segments':self.segments,
        }
        
    def Validate(self, fd):
        """
        Validates a file-like object to determine if its a valid PNG file.

        :param fd: file descriptor (file-like)
        :return: True on valid PNG, False otherwise (bool)
        """
        # Need to make a big clean up of this code, PNG was the first validator implemented, because
        # of the format being so clear, and simple. Also, thanks to CRC blocks at the end of
        # segments, is the most precise validator implemented yet.
        self.fd = fd
        valid_chunks_list = self.valid_chunks_list
        valid_chunks = valid_chunks_list[0]
        self.is_valid = True
        self._SetValidBytes(0)
        self.eof = False
        self.end = False
        self.segments = []
        header = self._Read(8)
        self.is_valid = header == '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'
        self._CountValidBytes(8)
        while self.is_valid and not self.eof:
            seg_name = ""
            seg_offset = self.fd.tell()
            seg_len = None
            seg_crc1 = None
            seg_crc2 = None
            chunk_length_raw = self._Read(4)
            self._CountValidBytes(4)
            chunk_name = self._Read(4)
            seg_name = chunk_name
            if chunk_name in valid_chunks:  # this is a bit strict with non-standard valid chunks
                self._CountValidBytes(4)
                chunk_length = self._ConvertBytes(chunk_length_raw, "uL")
                seg_len = chunk_length + 8
                if chunk_length > self.max_chunk_length:
                    self.is_valid = False
                    break
                chunk_data = self._Read(chunk_length)
                #chunk_data = fd.read(chunk_length)
                # we'll only count the data bytes as valid if the CRC is valid
                chunk_crc_raw = self._Read(4)
                chunk_crc = self._ConvertBytes(chunk_crc_raw, "sL")
                calc_crc = zlib.crc32(chunk_name + chunk_data)
                seg_crc1 = chunk_crc
                seg_crc2 = calc_crc
                if calc_crc == chunk_crc:
                    self._CountValidBytes(chunk_length + 4)  # so we count both data and CRC bytes
                else:
                    self.is_valid = False
                #is_valid = calc_crc == chunk_crc
                if chunk_name == "IHDR":
                    valid_chunks = valid_chunks_list[1]
                elif chunk_name == "IEND":
                    valid_chunks = valid_chunks_list[2]
                    self._CountValidBytes(1)  # small fix
                    self.end = True
            else:
                is_valid = chunk_name == ""  # benefit of doubt for an incomplete file
                # should add some logic to interpret non-standard chunks
            self.segments.append((seg_name, seg_offset, seg_len, seg_crc1, seg_crc2))
        #premature_eof = eof and not end
        #self.is_valid = is_valid
        #self.eof = premature_eof
        #self.bytes_last_valid = bytes_last_valid
        # this 4 lines are left here for review -- should we add a self.end attribute to Validator
        # to track the occurrence of the valid-ending-structure in a file? that would replace the
        # old premature_eof logic and overall improve the information that a Validator returns.
        return self.is_valid#  and not self.eof
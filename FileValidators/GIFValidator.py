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

from Validator import Validator


class GIFValidator(Validator):
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
        super(GIFValidator, self).__init__()
        # this is later repeated in _Cleanup(), however PyCharm's code analyzer complains if
        # the attributes are not set in __init__()
        self.width = -1
        self.height = -1
        self.color_table_flag = False
        self.color_resolution = -1
        self.sort_flag = False
        self.color_table_size = -1
        self.background_color = -1
        self.pixel_aspect = -1
        self.color_table = []
        self.blocks = []
        # ---
        self.converters = {
            'uH': struct.Struct("<H"),
            'uB': struct.Struct("B"),
        }
        self.extension_blocks = {
            "\x01": "Plain Text Extension",
            "\xff": "Application Extension",
            "\xfe": "Comment Extension",
            "\xf9": "Graphics Control Extension",
        }

    def _Cleanup(self):
        """
        Cleans up the internal state of the validator.

        :return:
        """
        self.is_valid = False
        self.bytes_last_valid = 0
        self.eof = False
        self.end = False
        self.width = -1
        self.height = -1
        self.color_table_flag = False
        self.color_resolution = -1
        self.sort_flag = False
        self.color_table_size = -1
        self.background_color = -1
        self.pixel_aspect = -1
        self.color_table = []
        self.blocks = []

    def _ConvertBytes(self, value, t):
        """
        Converts packed bytes to int, signed long (t="sL") or signed shorts (t="sH").

        :param value: packed binary value (string)
        :param t: type, either "sH" or "sL" (string)
        :return: unpacked value (int)
        """
        return self.converters[t].unpack(value)[0]

    def GetDetails(self):
        """
        Returns dictionary with import information from the recently-validated file.

        :return: dictionary {

        }
        """
        return {
            "width": self.width,
            "height": self.height,
            "color_table_flag": self.color_table_flag,
            "color_resolution": self.color_resolution,
            "sort_flag": self.sort_flag,
            "color_table_size": self.color_table_size,
            "background_color": self.background_color,
            "pixel_aspect": self.pixel_aspect,
            "color_table": self.color_table,
            "blocks": self.blocks,
        }
        
    def Validate(self, fd):
        """
        Validates a file-like object to determine if its a valid PNG file.

        :param fd: file descriptor (file-like)
        :return: True on valid PNG, False otherwise (bool)
        """
        # Being a new validator, we're trying some different things here to see how they behave
        # and if they're worth porting to the others -- for example, return-on-invalid.
        self._Cleanup()
        self.fd = fd
        buff = self._Read(13)
        signature = buff[0: 3]
        version = buff[3: 6]
        log_scr_desc = buff[6:]  # better than LSD for Logical Screen Descriptor...
        self.is_valid = (signature == "GIF") and (version in {"87a", "89a"})
        self._CountValidBytes(6)
        if not self.is_valid:
            return False
        self.width = self._ConvertBytes(log_scr_desc[0: 2], "uH")
        self.height = self._ConvertBytes(log_scr_desc[2: 4], "uH")
        packed_info = ord(log_scr_desc[4])
        self.color_table_flag = bool(packed_info & 0b10000000)
        self.color_resolution = (packed_info & 0b01110000) >> 4
        self.sort_flag = bool(packed_info & 0b00001000)
        self.color_table_size = 2 << (packed_info & 0b00000111)
        self.background_color = ord(log_scr_desc[5])
        self.pixel_aspect = ord(log_scr_desc[6])
        self._CountValidBytes(7)
        if self.color_table_flag:
            buff = self._Read(3 * self.color_table_size)
            self.color_table = [(ord(buff[x * 3]), ord(buff[(x * 3) + 1]), ord(buff[(x * 3) + 2]))
                                for x in xrange(self.color_table_size)]
            self._CountValidBytes(3 * self.color_table_size)
        sub_block_bytes = 0  # this is needed for a sub-block reading
        while self.is_valid and not self.eof and not self.end:
            block_pos = self.fd.tell()
            block_id = self._Read(1)
            self.is_valid = block_id in {",", "!", ";"}
            self._CountValidBytes(1 + sub_block_bytes)
            sub_block_bytes = 0
            if not self.is_valid:
                return False
            if block_id == ";":  # end of GIF structure
                self.end = True
                self.blocks.append(("Trailer", block_pos))
                return self.is_valid  # which as far as i can tell, will always be True
            elif block_id == "!":
                # how many subtypes of extension blocks are? 4:
                # plaintext (0x01), application (0xff), comment (0xfe), graphics control (0xf9)
                # each extension block subtype has a "header" that defines some information and
                # the is followed by data sub-blocks, so we read the specific header and then leave
                # the file pointer pointing at the first data sub-block.
                ext_label = self._Read(1)
                sub_block_bytes += 1
                self.is_valid = ext_label in {"\x01", "\xff", "\xfe", "\xf9"}
                if not self.is_valid:
                    return False
                block_name = self.extension_blocks[ext_label]
                self.blocks.append((block_name, block_pos))
                if ext_label in {"\x01", "\xff", "\xf9"}:
                    # plaintext extension and application extension have the same kind of sub-header
                    eb_size = self._Read(1)
                    if self.eof:
                        self._CountValidBytes(sub_block_bytes)
                        return self.is_valid
                    eb_size = self._ConvertBytes(eb_size, "uB")
                    data = self._Read(eb_size)
                    sub_block_bytes += eb_size + 1
                # comment extension has no sub-header, it jumps straight to data sub-blocks, so
                # there's no need to consider it further.
            elif block_id == ",":
                # an image segment
                self.blocks.append(("Image Descriptor", block_pos))
                buff = self._Read(9)
                if self.eof:
                    return self.is_valid
                sub_block_bytes += 9
                #left = self._ConvertBytes(buff[0: 2], "uH")
                #top = self._ConvertBytes(buff[2: 4], "uH")
                #width = self._ConvertBytes(buff[4: 6], "uH")
                #height = self._ConvertBytes(buff[6: 8], "uH")
                packed_info = ord(buff[8])
                #print "Image: %d, %d, %d, %d" % (left, top, width, height)
                # i'm thinking of validating left, top, width and height, but i'm a bit unsure if
                # there's anything standard about that.
                local_table_flag = bool(packed_info & 0b10000000)
                local_table_size = 2 << (packed_info & 0b00000111)
                if local_table_flag:
                    local_table = self._Read(3 * local_table_size)
                    sub_block_bytes += local_table_size
                lzw_min = self._Read(1)
                sub_block_bytes += 1
            # and now we must interpret the sub-blocks until we find one with length 0, and then
            # we'll be standing in a block identifier.
            sb_size = 1  # this is a mock value to force the first iteration of the loop
            while sb_size > 0:
                sb_size = self._Read(1)
                sub_block_bytes += 1
                if self.eof:
                    self._CountValidBytes(sub_block_bytes)
                    return self.is_valid
                sb_size = self._ConvertBytes(sb_size, "uB")
                #print "sb_size: %d" % (sb_size)
                data = self._Read(sb_size)
                #print "%s" % (data.encode("hex"))
                sub_block_bytes += sb_size
            # now we have read all the data sub-blocks and our file pointer should be standing on
            # the following block
        return self.is_valid
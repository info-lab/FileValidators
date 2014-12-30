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


class JPGValidator(Validator):
    """
    Class that validates an object to determine if it is a valid JPG file.
    """

    def __init__(self):
        """
        Calls Validator.__init__() and sets some internal attributes for the validation process.

        :var converter: a Struct object used for byte-to-int unpacking. (struct.Struct)
        :var markers: a list of 2-byte strings that determines valid JPG markers. Can be extended
            to include non-standard markers that might have been omitted.  (list of strings)
        :var restart_markers: a list of 2-byte strings that determines valid restart markers for
            data segments. Should not be changed under any circumstance. (list of strings)
        :var chunksize: controls the size of chunks that are read when looking for the end of a
            data segment. Larger values may result in improved validating speed. (int)
        """
        super(JPGValidator, self).__init__()
        self.converter = struct.Struct(">H")
        self._chunksize = 2048  # should be fixed by now
        self.markers = {'\xff\xc0', '\xff\xc1', '\xff\xc2', '\xff\xc3', '\xff\xc4', '\xff\xc5',
            '\xff\xc6', '\xff\xc7', '\xff\xc8', '\xff\xc9', '\xff\xca', '\xff\xcb', '\xff\xcc',
            '\xff\xcd', '\xff\xce', '\xff\xcf', '\xff\xd0', '\xff\xd1', '\xff\xd2', '\xff\xd3',
            '\xff\xd4', '\xff\xd5', '\xff\xd6', '\xff\xd7', '\xff\xd9', '\xff\xda', '\xff\xdb',
            '\xff\xdc', '\xff\xdd', '\xff\xde', '\xff\xdf', '\xff\xe0', '\xff\xe1', '\xff\xe2',
            '\xff\xe3', '\xff\xe4', '\xff\xe5', '\xff\xe6', '\xff\xe7', '\xff\xe8', '\xff\xe9',
            '\xff\xea', '\xff\xeb', '\xff\xec', '\xff\xed', '\xff\xee', '\xff\xef', '\xff\xf0',
            '\xff\xf1', '\xff\xf2', '\xff\xf3', '\xff\xf4', '\xff\xf5', '\xff\xf6', '\xff\xf7',
            '\xff\xf8', '\xff\xf9', '\xff\xfa', '\xff\xfb', '\xff\xfc', '\xff\xfd', '\xff\xfe'}
        self.restart_markers = {'\xff\x00', '\xff\xd0', '\xff\xd1', '\xff\xd2', '\xff\xd3',
            '\xff\xd4', '\xff\xd5', '\xff\xd6', '\xff\xd7'}
        self.eoi_marker = False
        self.markers_found = []
        self.data = ""
        self.pos = 0

    def _ConvertBytes(self, value):
        """
        Handles internal byte conversion from packed-binary to int value.

        :param value: bytes to be converter (str)
        :return: unpacked value (int)
        """
        return self.converter.unpack(value)[0]

    def _Read(self, length):
        ret = self.data[self.pos: self.pos + length]
        if len(ret) < length:
            self.eof = True
        self.pos += length
        return ret

    def GetDetails(self):
        """
        Returns dictionary with import information from the recently-validated file.

        :return: dictionary {
            'segments': list of tuples of markers read from the file with the following structure:
                (marker (string), offset in file (int), length (int))
                length considers both the marker and the payload length, so you can seek the
                offset, read length bytes and get the whole segment.
            }
        """
        return {
            "segments": self.markers_found,
            'extensions': ['.jpg'],
        }

    def Validate(self, fd):
        """
        Validates a file-like object to determine if its a valid JPG file.

        :param fd: file-like object open for binary reading (file-like)
        :return: True on a valid JPG file, False otherwise (bool)
        """
        valid_markers = self.markers
        valid_restart_markers = self.restart_markers
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
        self.markers_found = []
        first_read = self._Read(4)  # we replace 2 consecutive reads for 1 and some logic
        header_marker = first_read[0:2]
        current_marker = first_read[2:4]
        #print header_marker, current_marker
        read_next_marker = True
        self.is_valid = header_marker == '\xff\xd8' and (current_marker in valid_markers)
        if self.is_valid and not self.eof:
            self.markers_found.append(('\xff\xd8', self.pos - 4, 2))
        self._CountValidBytes(4)
        is_eoi_marker = current_marker == '\xff\xd9'
        while not self.eof and not is_eoi_marker and self.is_valid:
            #print current_marker.encode("hex")
            #print "Marker: %s" % (current_marker.encode("hex"))
            if current_marker == '\xff\xd9':
                is_eoi_marker = True
                break
            if current_marker == '\xff\xdd':  # this marker has a fixed length of 2, it is the
            # only marker that has a fixed length, apart from FFD8 and FFD9.
                payload_length = 4
            else:
                payload_length = self._Read(2)
                self._CountValidBytes(2)
                if not self.eof:
                    payload_length = self._ConvertBytes(payload_length) - 2
                else:
                    payload_length = 0
            if self.is_valid and not self.eof:
                self.markers_found.append((current_marker, self.pos - 4,
                    payload_length + 4))  # we add 2 from the length, and 2 from the marker
            data = self._Read(payload_length)
            # data could/should be used to validate, maybe something to do with quantization
            # tables? should do a deeper research on markers and their data
            self._CountValidBytes(payload_length)
            eof = self.eof
            pos = 0
            while not eof and (current_marker == '\xff\xda') and pos >= 0:
                #print "self.pos: %d, pos: %d..." % (self.pos, pos),
                file_tell = self.pos
                adjust_offset = 0
                #bytestring = self.fd.read(self._chunksize)  # we don't use self._Read() because
                bytestring = self.data[self.pos:]  # we don't use self...
                # segment plus the EOI marker, and all that is less than self._chunksize.
                # In that case, setting the self.eof flag (through self._Read()) would be
                # wrong and/or messy.
                eof = len(bytestring) < self._chunksize
                seek_marker = True
                pos = bytestring.find("\xff")
                remark_counter = 0
                while seek_marker and pos >= 0:
                    remark_counter += 1
                    #adjust_offset += pos
                    potential_marker = bytestring[pos: pos + 2]
                    if not(potential_marker in valid_restart_markers):
                        current_marker = potential_marker
                        seek_marker = False
                        read_next_marker = False
                        self._SetValidBytes(file_tell + pos + 2)
                        #self.fd.seek(file_tell + adjust_offset + 2)
                        self.pos = file_tell + pos + 2
                    else:
                        adjust_offset += 2
                        self._CountValidBytes(adjust_offset)
                        #bytestring = bytestring[pos + 2:]
                        seek_marker = "\xff" in bytestring
                    pos = bytestring.find("\xff", pos + 1)
                #print remark_counter
            if read_next_marker:
                current_marker = self._Read(2)
            self.is_valid = current_marker in valid_markers
            self._CountValidBytes(2)
            read_next_marker = True
            is_eoi_marker = current_marker == '\xff\xd9'
        if is_eoi_marker:
            self._SetValidBytes(self.bytes_last_valid - 2)  # small fix to valid bytes length
            self.end = True
            self.markers_found.append(('\xff\xd9', self.pos - 2, 2))
        # The last marker should always be EOI/FFD9 and has a fixed length of 0
        return self.is_valid
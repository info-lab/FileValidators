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

    def _ConvertBytes(self, value, t):
        """

        :return: unpacked value (int)
        """
        pass
        #return self.converters[t].unpack(value)[0]

    def GetDetails(self):
        """
        Returns dictionary with import information from the recently-validated file.

        :return: dictionary {

        }
        """
        return {
        }
        
    def Validate(self, fd):
        """
        Validates a file-like object to determine if its a valid PNG file.

        :param fd: file descriptor (file-like)
        :return: True on valid PNG, False otherwise (bool)
        """
        pass
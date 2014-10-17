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
import array

from Validator import Validator


class SQLiteValidator(Validator):
    """
    Class that validates an object to determine if it is a valid SQLite 3 file.
    """
    def __init__(self):
        """
        Calls Validator.__init__() and sets some internal attributes for the validation process.
        """
        super(SQLiteValidator, self).__init__()
        self._Cleanup()
    
    def _ConvertBytes(self, value, size, big_endian=True):
        ret_value = array.array(size, value)
        if big_endian:
            ret_value.byteswap()
        return ret_value[0]

    def _Cleanup(self):
        """
        Cleans up all the internal attributes that are set by the Validate method(s) when a file is
        analyzed. It is also useful when first instantiating the object.

         The other validators do this inside the Validate method, however in this case it was a lot
         longer and the _Cleanup() method was needed.
        """
        self.is_valid = False
        self.bytes_last_valid = 0
        self.eof = False
        self.end = False
        self.page_size = -1
        self.usable_page_size = -1
        self.file_format_write_version = -1
        self.file_format_read_version = -1
        self.reserved_bytes_per_page = -1
        self.maximum_payload_fraction = -1
        self.minimum_payload_fraction = -1
        self.leaf_payload_fraction = -1
        self.file_change_counter = -1
        self.page_count = -1
        self.freelist_trunks = []
        self.freelist_total_count = -1
        self.schema_format_number = -1
        self.page_cache_size = ""
        self.largest_root_vacuum = -1
        self.database_encoding = -1
        self.user_version = ""
        self.incremental_vacuum = -1
        self.version_valid_for_number = -1
    
    def _ValidateHeader(self):
        """
        Validates the header of a SQLite 3 Format file. Returns nothing, just changes internal
        attributes of the object.
        """
        header = self._Read(100)
        header_descriptor = header[0:16]
        self.page_size = self._ConvertBytes(header[16:18], "H")
        self.file_format_write_version = self._ConvertBytes(header[18:19], "B")
        self.file_format_read_version = self._ConvertBytes(header[19:20], "B")
        self.reserved_bytes_per_page = self._ConvertBytes(header[20:21], "B")
        self.maximum_payload_fraction = self._ConvertBytes(header[21:22], "B")
        self.minimum_payload_fraction = self._ConvertBytes(header[22:23], "B")
        self.leaf_payload_fraction = self._ConvertBytes(header[23:24], "B")
        self.file_change_counter = self._ConvertBytes(header[24:28], "L")
        self.page_count = self._ConvertBytes(header[28:32], "L")
        self.freelist_trunks = [self._ConvertBytes(header[32:36], "L")]
        self.freelist_total_count = self._ConvertBytes(header[36:40], "L")
        self.schema_format_number = self._ConvertBytes(header[44:48], "L")
        self.page_cache_size = header[48:52]
        self.largest_root_vacuum = self._ConvertBytes(header[52:56], "L")
        self.database_encoding = self._ConvertBytes(header[56:60], "L")
        self.user_version = header[60:64]
        self.incremental_vacuum = self._ConvertBytes(header[64:68], "L") != 0
        reserved_for_expansion = header[68:92]
        self.version_valid_for_number = self._ConvertBytes(header[92:96], "L")
        # following line is VERY important
        self.is_valid_page_count = (self.page_count > 0) and\
                                   (self.file_change_counter == self.version_valid_for_number)
        # debugging for a valid page count:
        #print "self.page_count: %d" % (self.page_count)
        #print "file_change_counter: %d" % (file_change_counter)
        #print "version_valid_for_number: %d" % (version_valid_for_number)
        self.is_valid = ((header_descriptor == "SQLite format 3\x00") and 
            (self.file_format_write_version in [1, 2]) and
            (self.file_format_read_version in [1, 2]) and
            (self.maximum_payload_fraction == 64) and
            (self.minimum_payload_fraction == 32) and
            (self.leaf_payload_fraction == 32) and
            (self.schema_format_number in [1, 2, 3, 4]) and
            (self.database_encoding in [1, 2, 3]) and
            (reserved_for_expansion == ('\x00' * 24)))
        # end of _ValidateHeader, does not return anything.
        
    def _ValidatePages(self):
        """
        Validates the pages of a SQLite 3 Format file. Returns nothing, just changes internal
        attributes of the object.
        """
        if not self.is_valid:
            return
        # we only work on pages if header validation was successful
        # if header was valid, we consider the whole first page valid.
        #print "Still valid? ", self.is_valid
        #print "Page count: ", self.page_count
        self._CountValidBytes(self.page_size)
        self.usable_page_size = self.page_size - self.reserved_bytes_per_page
        ptr_map_pages_pointers = self.usable_page_size / 5
        ptr_map_pages = []
        if self.largest_root_vacuum > 0:
            if not self.is_valid_page_count:
                # we have ptrMap pages, so we can find out the real page_count and fix it
                self.fd.seek(self.page_size)
                page = self._Read(self.page_size)
                ptr_page = 3 + ptr_map_pages_pointers
                ptr_map_eof = False
                new_page_count = 2
                new_ptr_page = False
                valid_record_types = ['\x01', '\x02', '\x03', '\x04', '\x05']
                while not ptr_map_eof:
                    # we seek the end of the ptrMap chain and count all the pages referenced
                    # by them
                    if new_ptr_page:
                        new_ptr_page = False
                        new_page_count += 1
                    record_num = 0
                    while not ptr_map_eof and (record_num < ptr_map_pages_pointers):
                        ptr_record = page[record_num * 5: (record_num * 5) + 5]
                        record_type = ptr_record[0]
                        # it it's an empty record, that means end of ptr map chain
                        ptr_map_eof = ptr_record == ('\x00' * 5)
                        if ptr_map_eof and (record_num == 0):
                            # miss-identified content as a ptrPage
                            new_page_count -= 1
                        if (not ptr_map_eof and (record_num != 0)
                                and not record_type in valid_record_types):
                            # we found a corrupt ptr_map_page -- whole DB is corrupt
                            #print "Corrupt ptr_map_page."
                            #print ptr_record.encode("hex")
                            self.is_valid = False
                        if not ptr_map_eof and (record_type in valid_record_types):
                            # it's a valid pages record
                            new_page_count += 1
                        record_num += 1
                    self.fd.seek((ptr_page - 1) * self.page_size)
                    page = self._Read(self.page_size)
                    ptr_page += ptr_map_pages_pointers + 1
                    new_ptr_page = True
                #end while not(ptr_map_eof)
                self.page_count = new_page_count
                #print "New page count: ", new_page_count
                self.is_valid_page_count = True
            ptr_map_pages = [2]
        if self.is_valid_page_count:
            #print "valid page count!"
            # header page count was valid, so we rely on it
            if ptr_map_pages:
                ptr_page = 3 + ptr_map_pages_pointers
                while ptr_page < self.page_count:
                    ptr_map_pages.append(ptr_page)
                    ptr_page += ptr_map_pages_pointers + 1
                # now we know the location of all ptr_map_pages and can ignore them
            free_pages = []
            freelist_trunks = self.freelist_trunks
            current_page = 1
            self.fd.seek(self.page_size)
            page = "true"
            while self.is_valid and page and (current_page < self.page_count):
                page = self._Read(self.page_size)
                current_page += 1
                #print "Page: ", current_page
                # we walk all the DBs pages validating them
                if current_page in ptr_map_pages:
                    #print "ptrMap page"
                    # we ignore it, since it provides no valuable data
                    self._CountValidBytes(self.page_size)
                    continue
                if current_page in free_pages:
                    #print "free page"
                    # we have to ignore it
                    self._CountValidBytes(self.page_size)
                    continue
                if current_page in freelist_trunks:
                    #print "freelist trunk page"
                    # we have to analyze to find if there's a following freelist_trunk
                    # and add all the free pages to the freelist (so we can ignore them)
                    next_freelist_trunk = self._ConvertBytes(page[0:4], "L")
                    if next_freelist_trunk:
                        freelist_trunks.append(next_freelist_trunk)
                    freelist_records = self._ConvertBytes(page[4:8], "L")
                    record_pos = 8
                    for x in xrange(freelist_records):
                        free_pages.append(self._ConvertBytes(page[record_pos: record_pos + 4], "L"))
                        record_pos += 4
                    self._CountValidBytes(self.page_size)
                    continue
                # so its not a prtMap, not a freelist trunk or a free page.
                # its either a B-tree page or an cell payload overflow page
                # first we test for a B-tree page, then for a CPOP, if neither, then we call it
                # invalid and cut the validation
                #print "b-tree or cell payload overflow page"
                page_subheader = page[0:12]
                #print "Page subheader:", page_subheader.encode("hex")
                page_type_flag = self._ConvertBytes(page_subheader[0:1], "B")
                valid_page = page_type_flag in [2, 5, 10, 13]
                if page_type_flag in [2, 5]:
                    valid_page = self._ConvertBytes(page_subheader[8:12], "L") <= self.page_count
                if not valid_page:
                    # ok, does it look like a CPOP?
                    next_overflow_chain_page = self._ConvertBytes(page[0:4], "L")
                    valid_page = next_overflow_chain_page <= self.page_count
                self.is_valid = valid_page
                self._CountValidBytes(self.page_size)
            # end while
            if not page and (current_page < self.page_count):
                self.eof = True
        else:
            # header page count is not reliable, so we have to guess DB size
            #print "not valid page count!"
            if ptr_map_pages:
                # we have ptrMap pages to get the actual DB size in pages
                pass
            else:
                # we have to guess, maybe freelist?
                # if not freelist, one by one page analysis until first that doesn't match
                pass
            #end if ptr_map_pages
        #end if self.valid_page_count
        
    # end of _ValidatePages, does not return anything.
    
    def _ValidateDecompress(self):
        """
        Validates the structure of a SQLite 3 Format file. Returns nothing, just changes internal
        attributes of the object.

        Still not implemented.
        """
        pass
    # end of _ValidateDecompress, does not return anything.

    def GetDetails(self):
        """
        Returns a dictionary with detailed information about the last validated file.

        :return: dict of:
            * bytes_last_valid (int)
            * page_size (int)
            * usable_page_size (int)
            * file_format_write_version (int)
            * file_format_read_version (int)
            * reserved_bytes_per_page (int)
            * maximum_payload_fraction (int)
            * minimum_payload_fraction (int)
            * leaf_payload_fraction (int)
            * file_change_counter (int)
            * page_count (int)
            * freelist_trunks (list of ints)
            * freelist_total_count (int)
            * schema_format_number (int)
            * page_cache_size (string)
            * largest_root_vacuum (int)
            * database_encoding (int)
            * user_version (string)
            * incremental_vacuum (int)
            * version_valid_for_number (int)
        """
        return {
            'bytes_last_valid ': self.bytes_last_valid,
            'page_size ': self.page_size,
            'usable_page_size ': self.usable_page_size,
            'file_format_write_version ': self.file_format_write_version,
            'file_format_read_version ': self.file_format_read_version,
            'reserved_bytes_per_page ': self.reserved_bytes_per_page,
            'maximum_payload_fraction ': self.maximum_payload_fraction,
            'minimum_payload_fraction ': self.minimum_payload_fraction,
            'leaf_payload_fraction ': self.leaf_payload_fraction,
            'file_change_counter ': self.file_change_counter,
            'page_count ': self.page_count,
            'freelist_trunks ': self.freelist_trunks,
            'freelist_total_count ': self.freelist_total_count,
            'schema_format_number ': self.schema_format_number,
            'page_cache_size ': self.page_cache_size,
            'largest_root_vacuum ': self.largest_root_vacuum,
            'database_encoding ': self.database_encoding,
            'user_version ': self.user_version,
            'incremental_vacuum ': self.incremental_vacuum,
            'version_valid_for_number ': self.version_valid_for_number,
            'extensions': ['.sqlite'],
        }

    def Validate(self, fd):
        self.fd = fd
        self._Cleanup()
        self._ValidateHeader()
        self._ValidatePages()
        self._ValidateDecompress()
        return self.is_valid and not self.eof
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
# Based indirectly on Simson Garfinkel's MS-OLE file validator, complemented with docs from the
# OpenOffice project.
import array
import struct

from Validator import Validator


class MSOLEValidator(Validator):
    """
    Class that validates an object to determine if it is a valid MSOle file.
    """

    def __init__(self):
        """
        Calls to super().__init__(). No specific attributes are needed.
        """
        super(MSOLEValidator, self).__init__()
        # some initial values in case someone calls GetDetails() early:
        self.extension = []
        self.sector_size = -1
        self.sat = []
        self.msat = []
        self.msat_secs = []
        self.msat_secids = []
        self.sat_secs = -1
        self.max_sector = -1
        self.converters = {  # this dictionary defines the behaviour of _ConvertBytes, DO NOT TOUCH!
            'sH': struct.Struct("<h"),
            'sL': struct.Struct("<l"),
        }

    def _ConvertBytes(self, value, t):
        """
        Converts packed bytes to int, signed long (t="sL") or signed shorts (t="sH").

        :param value: packed binary value (string)
        :param t: type, either "sH" or "sL" (string)
        :return: unpacked value (int)
        """
        return self.converters[t].unpack(value)[0]

    def _FilterCDH(self, x):
        return x > -1

    def _FilterMsat(self, x):
        return x < -2

    def _FilterSat(self, x):
        return x < -4 or x > self.max_sector

    def _GetExtension(self):
        self.extension = []
        if self.is_valid:
            self.fd.seek(0)
            data = self.fd.read(self.bytes_last_valid)
            if "Word Document" in data:
                self.extension.append(".doc")
            if "Worksheet" in data:  # or "Workbook" in data:  # need to confirm this
                self.extension.append(".xls")
            if "PowerPoint" in data:
                self.extension.append(".ppt")
            # should change all this comparisons for one regex that matches and get the result from
            # a dict -- that should have better performance, though i doubt this might be a problem.

    def GetDetails(self):
        """
        Returns a dictionary with detailed information about the last validated file.

        :return: dict of:
            * sector_size (int)
            * msat (list of ints)
            * msat_secs (int)
            * msat_secids (list of ints)
            * sat_secs (int)
        """
        return {
            "sector_size": self.sector_size,
            "msat": self.msat,
            "sat": self.sat,
            "msat_secs": self.msat_secs,
            "msat_secids": self.msat_secids,
            "sat_secs": self.sat_secs,
            "extensions": self.extension,
            "max_sector": self.max_sector,
        }
        
    def Validate(self, fd):
        """
        Validates a file-like object to determine if its a valid MS-OLE file.

        :param fd: file descriptor (file-like)
        :return: True on valid MS-OLE, False otherwise (bool)
        """
        # GetDetails cleanup of variables
        self.extension = []
        self.sector_size = -1
        self.sat = []
        self.msat = []
        self.msat_secs = -1
        self.msat_secids = []
        self.sat_secs = -1
        self.max_sector = -1
        sector_size = -1  # i think this four variables should go away once cleanup is over
        # and rest of the initial setup
        self.fd = fd
        self.is_valid = True
        self._SetValidBytes(0)
        self.eof = False
        self.end = False
        cdh = self._Read(512)
        sector = ""
        header = cdh[0:8]
        byte_order = cdh[28:30]  # MS-OLE supports big endian and little endian data, however we
        # couldn't find a big endian file to check if the validator works correctly.
        ssz = self._ConvertBytes(cdh[30:32], "sH")
        # x and sat_secs are declared here to avoid referenced-before-assignment errors
        x_index = 0
        self.is_valid = ((header == '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1') and
                (byte_order == '\xfe\xff' or byte_order == '\xff\xfe') and
                (ssz >= 7) and len(cdh) == 512)
        if self.is_valid:
            # So far we have a valid CDH, now we have to:
            #   * build the MSAT
            #   * walk through the SAT, verifying with the MSAT the SAT-assigned sectors
            # The file will be valid as long as the SAT and MSAT are coherent between each other.
            # This method is based on Simson Garfinkel's S2 MS-OLE validator, with modifications
            # adapted from OpenOffice MS-OLE format description and methods to comply with the
            # Validation Framework.
            self._SetValidBytes(512)
            self.sector_size = 1 << ssz
            self.sat_secs = self._ConvertBytes(cdh[44:48], "sL")
            msat_secid = self._ConvertBytes(cdh[68:72], "sL")
            self.msat_secids.append(msat_secid)
            self.msat_secs = self._ConvertBytes(cdh[72:76], "sL")
            self.msat = array.array("l", cdh[76:512])
            file_location = -1
            while (msat_secid > -1) and not self.eof:
                new_location = 512 + (msat_secid * sector_size)
                if new_location <= file_location:
                    self.is_valid = False
                    break
                file_location = new_location
                try:
                    self.fd.seek(file_location)  # maybe _Read() should have a location parameter?
                except IOError:
                    self.is_valid = False
                    break
                sector_raw = self._Read(sector_size)
                if len(sector_raw) < sector_size:
                    break
                try:
                    sector = array.array("l", sector_raw)
                except ValueError:
                    self.is_valid = False
                    break
                msat_secid = sector[-1]
                self.msat.extend(sector[:-1])
                self.msat_secids.append(msat_secid)
            # We filter the MSAT to validate its length, everything higher than -1 is a valid
            # MSAT sector - then we compare against the CDH information.
            self.msat = filter(self._FilterCDH, self.msat)
            self.max_sector = len(self.msat) * (self.sector_size / 4)
            self.is_valid = self.is_valid and (len(self.msat) == self.sat_secs)
            #self.is_valid = self.is_valid and (filter(lambda(x): x < -2, msat) == [])
            self.is_valid = self.is_valid and (filter(self._FilterMsat, self.msat) == [])
            if self.is_valid and not self.eof:
                # Now we go through the SAT looking for sectors with value -3, and verifying that
                # they are also present in the MSAT. If we find a mismatch, that means we have a
                # corrupt file.
                # We also check for -4 in the SAT, which are MSAT sectors. Also, as a first check
                # we look for values lower than -4 or higher than self.max_sector, because they
                # are signs of a corrupt file.
                base_sector = 0
                base_sector_inc = self.sector_size / 4
                x_index = 0
                len_msat = len(self.msat)
                file_location = 512
                while self.is_valid and (x_index < len_msat) and not self.eof:
                    x = self.msat[x_index]
                    self._SetValidBytes(file_location + self.sector_size)
                    file_location = 512 + (x * self.sector_size)
                    try:
                        self.fd.seek(file_location)
                    except IOError:
                        self.is_valid = False
                        break
                    sector_raw = self._Read(self.sector_size)
                    if len(sector_raw) < self.sector_size:
                        self.is_valid = False
                        break
                    try:
                        sector = array.array("l", sector_raw)  # maybe ConvertBytes could take this?
                    except ValueError:
                        self.is_valid = False
                        break
                    #self.is_valid = filter(lambda(x): x < -4, sector) == []
                    self.is_valid = filter(self._FilterSat, sector) == []
                    self.sat.extend(sector)
                    for key, val in enumerate(sector, base_sector):
                        if val == -3:
                            if not(key in self.msat):
                                self.is_valid = False
                                break
                        elif val == -4:
                            if not(key in self.msat_secids):
                                self.is_valid = False
                                break
                    base_sector += base_sector_inc
                    x_index += 1
            else:
                pass
                #print "Bad MSAT."
        else:
            pass
        if self.is_valid and (x_index == self.sat_secs) and sector and not self.eof:
            # Validation is over and we analyzed the entire SAT. sector still has the contents of
            # the last SAT-sector. We will do a last step to calculate the real file size out of
            # this information:
            # We will reverse sector, and look for the first non -1 value in it, which is the last
            # assigned sector that the SAT has information about. We can't look for the first -1
            # found in sector because a MS-OLE valid file could have a -1 from a freed sector and
            # we'd be cutting short the file.
            last_sat = sector[:]
            last_sat.reverse()
            x = 0
            b = last_sat[x]
            while b == -1 and x < len(last_sat) - 1:
                x += 1
                b = last_sat[x]
            free_secs = x
            sat_secs = self.sat_secs
            sector_size = self.sector_size  # assign this variables for shortness un the next calc
            bytes_last_valid = 512 + ((((sat_secs - 1) * (sector_size / 4)) * sector_size)
                                + (((sector_size / 4) - free_secs) * sector_size))
            self._SetValidBytes(bytes_last_valid)
            self.end = True
        else:
            self.is_valid = False
        self._GetExtension()
        return self.is_valid  # and not(self.eof) # this was semantically flawed
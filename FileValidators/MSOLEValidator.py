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
        self.sector_size = -1
        self.msat = []
        self.msat_secs = []
        self.msat_secids = []

    def GetDetails(self):
        """
        Returns a dictionary with detailed information about the last validated file.

        :return: dict of:
            * sector_size (int)
            * msat (list of ints)
            * msat_secids (list of ints)

        """
        return {
            "sector_size": self.sector_size,
            "msat": self.msat,
            "msat_secs": self.msat_secs,
            "msat_secids": self.msat_secids,
        }
        
    def Validate(self, fd):
        # still needs cleanup to comply with the improved interface (_Read, _CountValidBytes and
        # _SetValidBytes)
        bytes_last_valid = 0
        eof = False
        cdh = fd.read(512)
        sector_size = -1
        sector = ""
        msat = []
        msat_secids = []
        msat_secs = []
        header = cdh[0:8]
        byte_order = cdh[28:30]
        ssz = array.array("h", cdh[30:32])[0]
        # x and sat_secs are declared here to avoid referenced-before-asignment errors
        sat_secs = array.array("h", cdh[44:48])[0]  # gotta check this against MS-OLE docs...
        sat_secs = -1  # double check this thing...
        x_index = 0
        is_valid = ((header == '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1') and
                (byte_order == '\xfe\xff' or byte_order == '\xff\xfe') and
                (ssz >= 7)
                and len(cdh) == 512)
        if is_valid:
            # So far we have a valid CDH, now we have to:
            #   * build the MSAT
            #   * walk through the SAT, verifying with the MSAT the SAT-assigned sectors
            # The file will be valid as long as the SAT and MSAT are coherent between each other.
            # This method is based con Simson Garfinkel's S2 MS-OLE validator, with modifications
            # adapted from OpenOffice MS-OLE format description and methods to comply with the
            # Validation Framework.
            bytes_last_valid = 512
            sector_size = 1 << ssz  # shift instead of pow, a lot closer to C code and readability
            sat_secs = array.array("l", cdh[44:48])[0]
            msat_secid = array.array("l", cdh[68:72])[0]
            msat_secids.append(msat_secid)
            msat_secs = array.array("l", cdh[72:76])[0]
            msat = array.array("l", cdh[76:512])
            while (msat_secid > -1) and not(eof):
                file_location = 512 + (msat_secid * sector_size)
                fd.seek(file_location)
                sector_raw = fd.read(sector_size)
                if len(sector_raw) < sector_size:
                    eof = True
                    break
                sector = array.array("l", sector_raw)
                msat_secid = sector[-1]
                msat.extend(sector[:-1])
                msat_secids.append(msat_secid)
            msat = filter(lambda(x): x > -1, msat)
            # We filter the MSAT to validate its length, everything higher than -1 is a valid
            # MSAT sector - then we compare against the CDH information.
            is_valid = (len(msat) == sat_secs) or eof
            is_valid = is_valid and (filter(lambda(x): x < -2, msat) == [])
            if is_valid and not eof:
                # Now we go through the SAT looking for sectors with value -3, and verifying that
                # they are also present in the MSAT. If we find a mismatch, that means we have a
                # corrupt file.
                # We also check for -4 in the SAT, which are MSAT sectors. Also, as a first check
                # we look for lower than -4 values, which would also indicate a corrupt file.
                base_sector = 0
                x_index = 0
                len_msat = len(msat)
                file_location = 512
                while is_valid and (x_index < len_msat) and not eof:
                    x = msat[x_index]
                    bytes_last_valid = file_location + sector_size
                    file_location = 512 + (x * sector_size)
                    fd.seek(file_location)
                    sector_raw = fd.read(sector_size)
                    eof = len(sector_raw) < sector_size
                    sector = array.array("l", sector_raw)
                    is_valid = filter(lambda(x): x < -4, sector) == []
                    for key, val in enumerate(sector, base_sector):
                        if val == -3:
                            if not(key in msat):
                                is_valid = False
                                break
                        elif val == -4:
                            if not(key in msat_secids):
                                is_valid = False
                                break
                    base_sector += sector_size / 4
                    x_index += 1
            else:
                pass
                #print "Bad MSAT."
        else:
            pass
        if is_valid and (x_index == sat_secs) and sector:
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
            while b == -1:
                x += 1
                b = last_sat[x]
            free_secs = x
            bytes_last_valid = 512 + ((((sat_secs - 1) * (sector_size / 4)) * sector_size)
                                + (((sector_size / 4) - free_secs) * sector_size))
        else:
            is_valid = False
        self.eof = eof
        self.bytes_last_valid = bytes_last_valid
        self.is_valid = is_valid
        self.sector_size = sector_size
        self.msat_secs = msat_secs
        self.msat = msat
        self.msat_secids = msat_secids
        return is_valid  # and not(self.eof) # this was semantically flawed
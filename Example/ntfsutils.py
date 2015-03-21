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

# The idea behind this module is that you can import some useful functions from the (i)python
# console. This functions help in pretty printing of the information return form
# NTFSRecordValidator.GetDetails().
#
# Mostly, this was needed for a special class in teaching the use of MFT information when analyzing
# a drive.


ATTRIBUTES_FIELDS = {
    0x10: [
        ("CTime", "Creation time"),
        ("ATime", "Altered time"),
        ("MTime", "MFT changed time"),
        ("RTime", "Read time"),
        ("Permissions", "File permissions"),
        ("MaxVersions", "Maximum number of versions"),
        ("VersionNumber", "Version number"),
        ("ClassID", "Class Id"),
        ("OwnerID", "Owner Id"),
        ("SecurityID", "Security Id"),
        ("QuotaCharged", "Quota Charged"),
        ("USN", "Update Sequence Number"),
    ]
}


def pretty_print(v):
    """
    Prints the values obtained from NTFSRecordValidator.

    :param v: an instance of NTFSRecordValidator.
    """
    valid, eof, last_valid, end = v.GetStatus()
    d = v.GetDetails()
    if valid:
        print "NTFS Record"
        if "Header" in d:
            header = d["Header"]
            print "Record Header:"
            flags = header["flags"]["InUse"] * "U" + header["flags"]["IsDir"] * "D"
            values = [
                ("0x00", "Magic number", header["magic"]),
                ("0x04", "Offset to update sequence", header["offset_update"]),
                ("0x06", "Size (words) of USN and USA", header["size_update"]),
                ("0x08", "$Logfile Sequence Number", header["lsn"]),
                ("0x10", "Sequence number", header["sequence_number"]),
                ("0x12", "Hardlink count", header["hardlink_count"]),
                ("0x14", "Offset to first attribute", header["offset_attribute"]),
                ("0x16", "Flags", flags),
                ("0x18", "Real size", header["size_real"]),
                ("0x1C", "Allocated size", header["size_alloc"]),
                ("0x20", "Base FILE record", header["base_record"]),
                ("0x28", "Next attribute ID", header["next_attribute"]),
                ("0x2A", "Align to 4-byte boundary", header["align"]),
                ("0x2C", "MFT record number", header["mft_number"]),
            ]
            print "    Offset Field                         Value    "
            print "    " + "=" * 46
            for v in values:
                offset, field, value = v
                field = field.ljust(30)
                print "    %s:  %s%s" % (offset, field, value)
        if "Attributes" in d:
            attributes = d["Attributes"]
            print "\nRecord Attributes:"
            for a in attributes:
                print "    %s" % (a["TypeName"])
                type = a["Type"]
                if a["Parsed"]:
                    attvars = ATTRIBUTES_FIELDS[type]
                    for v in attvars:
                        index, name = v
                        name = name.ljust(28,".")
                        if hasattr(a[index], "__iter__"):
                            print "        %s" % name
                            for i in a[index]:
                                elem = "%s" % i
                                elem = elem.ljust(24)
                                print "            %s%s" % (elem, a[index][i])
                        else:
                            print "        %s%s" % (name, a[index])
                else:
                    print "    (not parsed)"
    else:
        print "Non-valid NTFS Record"

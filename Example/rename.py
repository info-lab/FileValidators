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

import argparse
import cStringIO
import datetime
import FileValidators
import os


# A few constants:
DEBUG_BENCHMARK = True

# And now some variables:
validators = {
    '.jpg': FileValidators.JPGValidator(),
    '.png': FileValidators.PNGValidator(),
    '.doc': FileValidators.MSOLEValidator(),
    '.xls': FileValidators.MSOLEValidator(),
    '.ppt': FileValidators.MSOLEValidator(),
    '.zip': FileValidators.ZIPValidator(),
}


def ArgParse():
    """
    Parses the command line arguments

    :return: argparse dictionary
    """
    # parse command line arguments
    parser = argparse.ArgumentParser(
        description="rename: validates and renames files on a directory recursively.")
    parser.add_argument("ipath",
                        #nargs="+",  # may enable this later on
                        help="Input path.")
    parser.add_argument("opath",
                        #nargs="+",  # may enable this later on
                        help="Output path.")
    args = parser.parse_args()
    return args


def Validate(args):
    """
    Performs validation according to the command line arguments received.

    :param args: argparse dictionary.
    :return:
    """
    path = args.ipath
    oroot = args.opath
    for root, dirs, files in os.walk(path):
        for filename in files:
            extension = os.path.splitext(filename)[1]
            if extension in validators.keys():
                print filename,
                fd = open(os.path.join(root, filename), "rb", 1048576)
                data = fd.read()
                fd.close()
                fm = cStringIO.StringIO(data)
                v = validators[extension]
                v.Validate(fm)
                valid, eof, size, end = v.GetStatus()
                if valid:
                    print " valid"
                    new_exts = v.GetDetails()['extensions']
                    for ext in new_exts:
                        print "  --> %s" % (filename[: -4] + ext)
                        new_name = os.path.join(oroot, filename)[: -4] + ext
                        fo = open(new_name, "wb")
                        fo.write(data[:size])
                        fo.close()
                else:
                    print "invalid"
                fm.close()


def main():
    args = ArgParse()
    print args
    t1 = datetime.datetime.now()
    # actually i should make a CheckArgs() function
    if os.path.isdir(args.ipath) and os.path.isdir(args.ipath):
        Validate(args)
    else:
        print "ipath and opath arguments must be alid directorys!"
    dt = datetime.datetime.now() - t1
    if DEBUG_BENCHMARK:
        print "\nTime taken: %s" % dt


if __name__ == "__main__":
    main()
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
import datetime
import FileValidators
import os


# Logger classes
class CSVLogger(object):

    def __init__(self, fpath):
        self.fpath = fpath + ".csv"
        self.fd = None

    def Open(self):
        self.fd = open(self.fpath, "w")
        self.Log(["Start of log"])
        self.Log(["Time:", str(datetime.datetime.now())])

    def Close(self):
        self.Log(["End of log"])
        self.Log(["Time:", str(datetime.datetime.now())])
        if self.fd:
            self.fd.close()
            self.fd = None

    def Log(self, values, flag=None):
        data = ",".join(values) + "\n"
        if self.fd:
            #print data
            self.fd.write(data)


class HTMLogger(object):

    def __init__(self, fpath):
        self.path = fpath + ".html"
        self.fd = None

    def Open(self):
        self.fd = open(self.path, "w")
        self.fd.write("""
        <html>
        <head>
            <title>CIRA File Validators val.py results log</title>
        </head>
        <body>
            <h3>CIRA File Validators val.py results log</h3>
            <p>Start time: %s</p>
            <table style="border: 1px solid silver;">
        """ % datetime.datetime.now())

    def Close(self):
        if self.fd:
            self.fd.write("""
                </table>
                <p>End time: %s</p>
            </body>
            </html>
            """ % datetime.datetime.now())
            self.fd.close()
            self.fd = None

    def Log(self, values, flag=None):
        if flag is None:
            auxstyle = 'style="border: 1px solid silver;"'
        else:
            if flag:
                auxstyle = 'style="border: 1px solid silver; background-color: #afa;"'
            else:
                auxstyle = 'style="border: 1px solid silver; background-color: #faa;"'
        auxstring = '<td %s>' % auxstyle + '%s</td>'
        auxlist = [auxstring % v for v in values]
        data = "<tr>\n" + "\n".join(auxlist) + "\n</tr>\n"
        if self.fd:
            self.fd.write(data)


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
    '.ics': FileValidators.ICSValidator(),
    '.EML': FileValidators.EMLValidator(),
}

loggers = {
    'csv': CSVLogger,
    'html': HTMLogger,
}


def ArgParse():
    """
    Parses the command line arguments

    :return: argparse dictionary
    """
    # parse command line arguments
    parser = argparse.ArgumentParser(
        description="val: validates files on a directory recursively.")
    parser.add_argument("ipath",
                        #nargs="+",  # may enable this later on
                        help="Input path.")
    parser.add_argument("-f",
                        dest="format",
                        choices=["csv", "html"],
                        default="csv",
                        help="Output format.")
    parser.add_argument("-o",
                        dest="ofile",
                        default="validation-log",
                        help="Output file. Extension is added according to format -f.")
    args = parser.parse_args()
    return args


def Validate(args):
    """
    Performs validation according to the command line arguments received.

    :param args: argparse dictionary.
    :return:
    """
    path = args.ipath
    ofile = args.ofile
    fname_base = path + os.path.sep + "%s"
    logger = loggers[args.format](ofile)
    logger.Open()
    logger.Log(["Path", "Valid", "EOF", "Size", "End"])
    counter_valid = 0
    counter_invalid = 0
    for root, dirs, files in os.walk(path):
        for filename in files:
            extension = os.path.splitext(filename)[1].lower()
            if extension in validators.keys():
                fd = open(os.path.join(root, filename), "rb", 1048576)
                v = validators[extension]
                v.Validate(fd)
                fd.close()
                valid, eof, size, end = v.GetStatus()
                fname = fname_base % filename
                values = [fname, str(valid), str(eof), str(size), str(end)]
                logger.Log(values, valid)
                counter_valid += 1 * valid
                counter_invalid += 1 * (not valid)
    logger.Log(["Valid files:", "%d" % counter_valid])
    logger.Log(["Invalid files:", "%d" % counter_invalid])
    logger.Close()


def main():
    args = ArgParse()
    print args
    t1 = datetime.datetime.now()
    # actually i should make a CheckArgs() function
    if os.path.isdir(args.ipath):
        Validate(args)
    else:
        print "ipath argument must be a valid directory!"
    dt = datetime.datetime.now() - t1
    if DEBUG_BENCHMARK:
        print "\nTime taken: %s" % dt


if __name__ == "__main__":
    main()

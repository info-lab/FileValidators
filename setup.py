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
from distutils.core import setup
import FileValidators

long_desc = """"
A file validation framework based on Garfinkel's work described in "Carving contiguous and
fragmented files with fast object validation", 2007.

Some validators have drawn upon ideas found on Garfinkel's work, while others are entirely new. The
interface provided is similar to that which Garfinkel proposed, but there are some differences.

Currently supported formats:
* PNG
* JPG
* MS-OLE
* SQLite 3
* ZIP as a mock only -- it checks with zipfile.is_zipfile
"""

setup(
    name = "CIRA File Validation Framework",
    version = FileValidators.__VER__,
    description = "File validation framework for file carving applications.",
    long_description = long_desc,
    author = "InFo-Lab",
    #author_email = "info-lab@ufasta.edu.ar", this still isn't active, should be pretty soon
    url = "http://ciraframework.wordpress.com/",
    #url = "http://www.info-lab.org.ar/"
    packages = ['FileValidators'],
    
    )
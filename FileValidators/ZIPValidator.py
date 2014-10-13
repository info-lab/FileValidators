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
import zipfile

from Validator import Validator


class ZIPValidator(Validator):
    """
    Class that validates an object to determine if it is a valid ZIP file. Uses zipfile from the
    python standard library.
    """
    def __init__(self):
        """
        Calls super().__init__() and then sets the Validate attribute to point at  zipfile's
        is_zipfile() function.
        :return:
        """
        super(ZIPValidator, self).__init__()
        self.Validate = zipfile.is_zipfile
        # Instead of writing a Validate() method, we take a function from zipfile module and use it.
        
    def GetStatus(self):
        """
        Since Validate is replaced by zipfile's is_zipfile function, there's no real status we can
        return. Just to make sure nobody changes the values, GetStatus returns a fixed result.

        :return: False, False, -1, False
        """
        return False, False, -1, False
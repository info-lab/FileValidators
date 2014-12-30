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

"""
    Only ascii character.
    @TODO Detect if it is ANSI, UTF-8 or UNICODE. 

  ! " # $ % & ' ( ) * + , - . / 0 1 2 3 4 5 6 7 8 9 : ; < = > ? @ 
  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z [ \ ] ^ _ ` 
  a b c d e f g h i j k l m n o p q r s t u v w x y z { | } ~
"""
#import String

from Validator import Validator


class TXTValidator(Validator):
    """
    Class that validates if an object is a valid TXT file in spanish. 
	validate al text from 32 to 128, \n, \t  and character with tilde.
    """
    def __init__(self):
        """
        Calls super().__init__() and then sets the Validate attribute to point at  zipfile's
        is_zipfile() function.
        :return:
        """
        super(TXTValidator, self).__init__()
        self.max_chunk_length = (1024 * 1024) * 40  # when the validators are used as workers for
        # a file structure based carver, this can lead to (very) bad behaviour, so we define a
        # maximum length for a valid PNG. Not entirely standard, but most surely a PNG reporting
        # chunk lengths of a few GiB is a corrupt PNG.
        # 40 MiB should cover *most* cases, but it can be adjusted.
        self.segments = []
        self.data = ""
        self.pos = 0
        


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
            'segments': a list of tuples of the following format:
                (segid (string), offset (int), length (int), CRC-32 (long), CRC-32 calc (long))
                Segment segid is found at offset bytes in the file, takes up length bytes (count
                from the segid offset including the CRC-32 and the calculated CRC-32)
        }
        """
        return {
            'extensions': ['txt'],
        }

    def Validate(self, fd):
        """
        Validates a file-like object to determine if its a valid PNG file.

        :param fd: file descriptor (file-like)
        :return: True on valid TXT, False otherwise (bool)
        """
	valid_list = []
        self.pos = 0
        if type(fd) == file:
            self.data = fd.read()
        elif type(fd) == str:
            self.data = fd
        else:
            raise Exception("Argument must be either a file or a string.")
	"""
	    Standar Character
	"""
	for i in range(32, 126+1):
	    valid_list.append(chr(i)),
	valid_list.append("\n")
	valid_list.append("\t")
	
	"""
	    Extended Character
	"""
	for i in range(128, 168+1):
	    valid_list.append(chr(i)),
	
        self.is_valid = True
        self._SetValidBytes(0)
        self.eof = False
        self.end = False
	print "Start \n"
	text = self._Read(1)

        while self.is_valid and not self.eof and not self.end:
	    print "%s " % (text)
	    if text in valid_list:
		self.is_valid = True
		self._CountValidBytes(1)
	    else:
		self.is_valid = False
    	    text = self._Read(1)

	return self.is_valid

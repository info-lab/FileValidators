Version 0.5.1:
--------------
* Validator._Read() method handles reading and length-checking. All that bureaucracy is taken from 
the Validate() methods, which results in cleaner code.
* JPGValidator.GetDetails() method implemented.
* PNGValidator.GetDetails() method implemented.
* Fixed a small bug in JGPValidator() which counted 2 extra bytes at the end of a valid JPG file.
* Fixed a small bug in PNGValidator() which counted 1 less byte at the end of a valid PNG file.
* Code cleanup complete on:
    * JPGValidator
    * PNGValidator
* Still missing cleanup on:
    * MSOLEValidator
    * SQLiteValidator -- however this was far better than the others from the beginning.

Version 0.5:
------------
* Started translating from spanish to english in comments and docstrings. Some may still be in
spanish -- eventually all will be in english.
* Starting improvements in comments and docstrings.
* Moved GetStatus, _ConvertBytes, _CountValidBytes and _SetValidBytes to Validator.
* All validators work with _CountValidBytes, _ConvertBytes and _SetValidBytes. Mostly that leads to
clearer code in the Validate() method.
* Also, changing all uses of array.array to uses of struct.unpack (where applicable).
* Big code cleanup, Pylint and PyCharm's code inspector should give a lot less warnings.
* Validator.GetDetails() method, dummy method that always returns an empty dict.
* MSOLEValidator.GetDetails() method implemented.

Version 0.4.2:
--------------
* More fixes to JPGValidator, added Validator ABC, from which all validators inherit.

Version 0.4.1:
--------------
* Improved JPGValidator, now reads data segment in chunks instead of 1-byte reads.

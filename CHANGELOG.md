Version 0.6.1:
--------------
* Merged Pull request #1.
* Added FileValidators/xp directory. Here you can find experimental validators which may not work
in the same fashion as the other validators. Eventually they may be moved to the main module.
    * ZIPValidator2 is in need of cleanup and tests before it can replace ZIPValidator. Also, it is
    based in the old design that reads from file instead of buffer.
    * LNKValidator needs a validation algorithm and tests before it can be moved out.

Version 0.6:
------------
* So far, reimplementing means reading the whole file at the beginning of the Validate method and
then working from that buffer. All validators work with a buffer oriented implementation now. This
has resulted in the following performance changes:
    * GIFValidator reimplemented ()  - 1.1 to 3x faster
    * MSOLEValidator reimplemented.  - 3% to 20% faster
    * SQLiteValidator reimplemented. - 27% slower to 129% faster
    * JPGValidator reimplemented.    - 47% to 82% faster
* Due to the type check added at the beginning of the Validate method, validators will only work
against files (no StringIO objects) and strings (Python base strings, not bytearrays, etc).
    * This shouldn't be a major problem, since working from a string has made it unnecessary to
    use StringIO objects.
* The new design should allow for new, faster algorithms.
* Work is needed to implement a way to validate chunks of files, so that really big files (gigabyte
sized and bigger) can be validated without causing out-of-memory faults.

Version 0.5.6:
--------------
* Tests with Orthrus proved the current architecture to be slow for carver integration: 
    * Current file-oriented design means a StringIO object has to be created for every test in the
    carver.
    * That means reading the file in the first place, and then creating the object.
    * And using method calls to another object for every read operation.
* The file-oriented design also brought its own problems in JPGValidator and GIFValidator.
* The new PNGValidator is buffer-oriented and is 10 to 66% faster than the old code:
    * 10% faster for small files read from disk
    * 33% faster for normal to big files read from disk
    * 66% faster when validating a string -- this also means that the carver won't have to create a
    StringIO object, which will aso save time for the carver.
* The new architecture will be tested as the validators are ported to it. The interface will not
change, but now accepts strings.
* As of now, it works on whole files loaded to memory. Further improvements should allow to validate
large files in chunks of a given size.

Version 0.5.5:
--------------
* GIFValidator implemented and tested against a simple test suite.

Version 0.5.4:
--------------
* Tests against a real case showed room for improvement in MSOLEValidator.
* Added 'extensions' to the GetDetails() dictionary. This is useful in cases such as MS-OLE, where
the same format has sub-formats which should be identified.
    * This was added as a list of extensions in case the sub-format test is not conclusive.
* All validators (except ZIPValidator) support the 'extensions' keyword in GetDetails().
* Examples/rename.py is new utility that moves/renames valid files according to their real
extension, as far as the validator can tell. 

Version 0.5.3:
--------------
* Small improvements, bug-fixes and cleanup documented in the various commits to the repository.
* Example/val.py is the new application that shows the use of validators, both from a developer
and from a users point of view.

Version 0.5.2:
--------------
* Finished cleanup on MSOLEValidator and SQLiteValidator. Please bear in mind, however, that the 
SQLite Validator is still a work in progress and needs more polishing.
* MSOLEValidator.GetDetails() method improved.
* SQLiteValidator.GetDetails() method implemented. 
* Added Validator.end attribute, that means that:
    * Validator.eof answers "has the validator reached EOF?", or more precisely, "has the validator
    tried to read bytes unsuccessfully?". This is tracked directly from Validator._Read().
    * Validator.end answers "has the end of file structure been reached?"
* Validator.GetStatus() now also returns Validator.end as part of the tuple.

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

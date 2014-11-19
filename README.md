FileValidators
==============

Description
-----------
A validator is a small program, object or function that can tell if a given object (a file in most
cases) is a valid file according to the standard or the description of a file format. Validators are
very useful in the context of file carving, because they help avoid recovering, sorting and going
through (hundreds of) thousands of invalid files.

Some carving programs perform file validation before extracting the files and filter the results,
but this is not standard, and might even be unwanted behaviour. This framework provides an
interface to validate files, and can work from the inside a file carver or a stand-alone application
that validates already existing files (see Example/validators-app.py).

These validators have been designed to "fail for inclusion", which means that when a validator 
cannot find telltale signs of a broken file, it will return True and leave the human validator (you)
to decide whether it is a valid file or not. 

Currently, validators have been implemented for the following formats:

* **JPG**
* **PNG** -- thanks to CRC checks, this validator will always give accurate results
* **GIF**
* **MS-OLE** file format (Office 97-2003, thumbs.db, etc)
* **SQLite3** -- partially finished, can parse valid DB's
* **ZIP** file format as only a True/False validator -- it can only tell valid files, but not give any
additional information.

---

This framework is based on the interface described by Simson Garfinkel in his 2007 paper "Carving
contiguous and fragmented files with fast object validation". This paper describes a file validation
framework in C++ that we decided to adapt to Python. Due to language differences and team choices,
we diverged from Garfinkel's original design, so the interfaces are not identical. Some of the
differences are:

* Validators work on file or string objects.
    * The new implementation reads all the file into an internal buffer, and validates the content.
    * It has broken some existing code in Orthrus, which was very implementation-dependent.
    * All the Example programs work correctly with the new implementation.
* Validator.Validate() method returns True or False. Additional information is queried to the
  validator through GetStatus() and GetDetails().
    * GetStatus() returns validating related information, including flags on EOF, file format end of
    file structure and the last valid byte.
    * GetDetails() returns a file format specific information, which varies between validators.
* In general, Garfinkel's framework is more tightly integrated with his file carver. We aimed for a
more general interface, which also allows to integrate the validators inside a file carver program.

Work in progress
----------------
We are currently working to support new file formats and improve the existing validators.

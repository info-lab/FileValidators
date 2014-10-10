Code Style in CIRA File Validators
==================================

* Lines are 100 chars wide.
* 4 spaces indent.
* Variables are underscored, lower case, eg: `a_variable`.
    * There are rare exceptions to this rule when there's a list comprehension or lambda function.
* Classes are Camel Case, eg: `UsefulClass`.
* Methods are Camel Case also, eg: `UsefulClass.UsefulMethod`.
    * Methods which should only be used internally by the validator start with an underscore, eg:
      `UsefulClass._InternalMethod`.
* A validator for a file format is named `[format name]Validator`, eg: `JPGValidator`, `PNGValidator`,
  etc.
* When in doubt, follow PEP-8.


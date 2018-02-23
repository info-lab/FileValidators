import struct
import collections

from Validator import Validator

class ICSValidator(Validator):

    def __init__(self):

        super(ICSValidator, self).__init__()
        self.data = ""
        self.flag_begin = False
        self.flag_version = False
        self.flag_end = False
        self.show_details = False
        self.counter_read = 0
        self.valid_objects_list = {  "ACTION","AUDIO","BEGIN","CALSCALE","CATEGORIES","CLASS","CONTACT","CREATED",
                                     "DESCRIPTION","DTEND","DTSTAMP","DTSTART","DURATION","END","EXDATE","FREEBUSY",
                                     "FREEBUSY","GEO","LAST-MODIFIED","LOCATION","METHOD","ORGANIZER","PRIORITY","PRODID",
                                     "RDATE","RECURRENCE-ID","RELATED-TO","REPEAT","REQUEST-STATUS","RRULE","SEQUENCE",
                                     "SEQUENCE","STATUS","STATUS","SUMMARY","TRANSP","TRIGGER","UID","URL","VERSION",
                                     "VEVENT"}
        self.last_valid_byte_min = 0
        self.last_valid_byte_max = 0
        self.count_bytes = 0
        self.list_description = []
        self.deq = collections.deque()
        self.objects_found = []
        

    def _Cleanup(self):
        """
        Cleans up the internal state of the validator.
        """
        self.data = ""
        self.flag_begin = False
        self.flag_version = False
        self.flag_end = False
        self.show_details = False
        self.counter_read = 0
        self.last_valid_byte_min = 0
        self.last_valid_byte_max = 0
        self.count_bytes = 0
        self.list_description = []
        self.deq = collections.deque()
        self.objects_found = []



    def _ReadByteRange(self,counter,length):

        self.last_valid_byte_min = counter
        self.last_valid_byte_max = counter + length
        print "\nThe error is between byte number: " + str(self.last_valid_byte_min) + " and: " + str(self.last_valid_byte_max)
    

    def _ByteLowerDetector(self,element,counter):
        string = list(element)
        for byte in element:
            if byte.islower():
                indx = string.index(byte)
                invalid_byte = counter + indx
                print "\nByte number " + str(invalid_byte) + " it is not uppercase"

    
    def _ByteExtendedASCIIDetector(self,element,counter):
        string = list(element)
        for byte in element:
            try:
                byte.decode('ascii')
            except UnicodeDecodeError:
                indx = string.index(byte)
                invalid_byte = counter + indx
                print "\nByte number " + str(invalid_byte) + " belongs to extended ASCII"
    

    def ShowDetailsError(self,fd):
        self.show_details = True
        self.Validate(fd)


    def ShowDescription(self):
        if not self.list_description:
            print "\nThe file has no description"
        else:
            print "\nDESCRIPTION:"
            print "".join([str(x) for x in self.list_description]).decode("string_escape")


    def GetDetails(self):
        
        return {
                "objects": self.objects_found,
                "description": self.list_description,
                "lines": self.counter_read,
            }

    def Validate(self,fd):

        var = True
        var_dif = 0
    
        if type(fd) == file:
            
            file_data = fd.read()
            self.data = [(l, len(k)) for l, k in zip(file_data.splitlines(), file_data.splitlines(True))]
            tam_max = len(self.data)
         
        elif type(fd) == str:
            self.data = fd
        else:
            raise Exception("Argument must be either a file or a string.")

        for element, length in self.data:
         
            var_description = False
            self.counter_read = self.counter_read + 1

            if (element[:length] == "BEGIN:VCALENDAR") and (self.counter_read == 1) and (length == 16 or length == 17) :
                self.flag_begin = True
                var_dif = length - len(element)
            if (element[:length] == ("VERSION:2.0" or "VERSION:1.0")) and (self.counter_read == 2) and (length == 12 or length == 13):
                self.flag_version = True    
            if (element[:length] == "END:VCALENDAR") and (self.counter_read == tam_max) and (length == 13):
                self.flag_end = True
                self.end = True

            try:
                element.decode('ascii')
            except UnicodeDecodeError:
                var = False
                if self.show_details == True:
                    print "\nLine has ASCII characters extended in: " + element
                    self._ReadByteRange(self.count_bytes,length - 1)
                    self._ByteExtendedASCIIDetector(element,self.count_bytes)

            left_text_object = element.partition(":")[0]
            right_text_object = element.partition(":")[2]
            left_text_description = element.partition(" ")[0]

            if left_text_object == "BEGIN":
                self.deq.append(right_text_object)
            if left_text_object == "END":

                try:
                    if not(right_text_object == self.deq.pop()):
                        var = False
                        if self.show_details == True:
                            print "\nBegin no coincide con END en: " + right_text_object
                except:
                    var = False
                    if self.show_details == True:
                        print "\nMayor cantidad de END que Begin"


            if left_text_object == "DESCRIPTION":
                self.list_description.append(right_text_object)
              
            if ((not left_text_description.islower() and not left_text_description.isupper()) or left_text_description.islower()) and not left_text_object.isupper():
                if ' ' in element[:1]:
                    self.list_description.append(element)
                    var_description = True
                
            if (len(element)+ var_dif) < length and var_description == False:
                var = False
                if self.show_details == True:
                    print "\nThe length of a line in the file does not match the length of the string in it: " + element
                    self._ReadByteRange(self.count_bytes,length - 1)

            if '  ' in element[2:]:
                var = False
                if self.show_details == True:
                    print "\nLine has more than one consecutive blank space in: " + element
                    self._ReadByteRange(self.count_bytes,length - 1)

            if left_text_object.isupper():
                var_aux = True
            else:
                if "DTSTART;TZID" in left_text_object:
                    var_aux = True
                elif "DTEND;TZID" in left_text_object:
                    var_aux = True
                elif var_description == False:
                    var = False
                    if self.show_details == True:
                        print "\nLine has a main object that is not uppercase in: " + left_text_object
                        self._ReadByteRange(self.count_bytes,length - 1)
                        self._ByteLowerDetector(left_text_object,self.count_bytes)
                    
            if left_text_object in self.valid_objects_list:
                self.objects_found.append(left_text_object)
            else:
                if "DTSTART;TZID" in left_text_object:
                    var_aux = True
                elif "DTEND;TZID" in left_text_object:
                    var_aux = True
                elif var_description == False:
                    var = False
                    if self.show_details == True:
                        print "\nThe object name is not valid: " + left_text_object
                        self._ReadByteRange(self.count_bytes,length - 1)

            self.count_bytes = self.count_bytes + length

        if var == True and self.flag_begin == True and self.flag_version == True and self.flag_end == True:
            print("\nValid iCalendar!")
            self.is_valid = True
            if self.show_details == True:
                self.show_details = False
            
        else:
            print("\nInvalid iCalendar!")
            self.is_valid = False
            if self.show_details == True:
                self.show_details = False
        

import email
from email.header import decode_header
import collections
import imaplib
import smtplib
import inspect
import struct


from Validator import Validator

class EMLValidator(Validator):

       
    def __init__(self):

        super(EMLValidator, self).__init__()
        self.data_mail = ""
        self._data_str = []
        self.filename = ""
        self.body = ""
        self.headers = []
        self.valid_headers_list = {"ARC-Authentication","ARC-Authentication-Results", "ARC-Message-Signature",
                                   "ARC-Seal", "Authentication-Results", "Bcc",
                                   "Cc", "Comments","Content-Disposition", "Content-Transfer-Encoding",
                                   "Content-Type", "DKIM-Signature", "Date", "Delivered-To",
                                   "Feedback-ID", "From", "In-Reply-To", "Keywords",
                                   "MIME-Version", "Message-ID", "Received", "Received-SPF",
                                   "References", "Reply-To", "Resent-Bcc", "Resent-Cc",
                                   "Resent-Date", "Resent-From", "Resent-Message-ID",
                                   "Resent-Sender", "Resent-To", "Return-Path", "Sender","Subject", "To",
                                   "X-Account-Notification-Type","X-Attachment-Id","X-Gm-Message-State",
                                   "X-Google-DKIM-Signature", "X-Google-Smtp-Source", "X-Notifications", "X-Received"}

        self.counter_read = 0
        self.count_bytes = 0
        self.boundary_mail = ""
        self.list_invalid = []
        self.deq = collections.deque()
        self.var_valid = True
        self.objects_found = []
        self.show_details = False
        file_data = []



    def _Cleanup(self):
        """
        Cleans up the internal state of the validator.
        """
        self.data_mail = ""
        self._data_str = []
        self.filename = ""
        self.body = ""
        self.headers = []
        self.count_bytes = 0
        self.boundary_mail = ""
        self.list_invalid = []
        self.deq = collections.deque()
        self.var_valid = True
        self.objects_found = []
        self.is_valid = False
        file_data = []



    def ShowDetailsError(self,fd):
        """
        shows details of where errors are found
        """
        self.show_details = True
        self.Validate(fd)

    
    def GetDetails(self):
        """
        Returns dictionary with import information from the recently-validated file.

        :return: dictionary {

        }
        """
        if self.var_valid == False:
            print(self.list_invalid)
        return {
                "body": self.body,
                "attached file": str(self.filename),
                "objects": self.objects_found,
                "lines": self.counter_read,
            }


    def _InvalidByteWSHeader(self, element, counter):
        """      
        returns in which byte is the whitespace and where it can be observed
        """
        string = list(element)
        for byte in element:
            if byte.isspace():
                indx = string.index(byte)
        invalid_byte = (counter + indx)
        if self.show_details == True:
            print ("\nByte number " + str(invalid_byte) + " it is a whitespace")
            print ("\nIn: " + element)


    def _InvalidByteExtendedASCII(self,element,counter):
        """            
        returns that byte is an extended ASCII and where it is observed
        """
        string = list(element)
        for byte in element:
            try:
                byte.decode('ascii')
            except UnicodeDecodeError:
                indx = string.index(byte)
                invalid_byte = counter + indx
        if self.show_details == True:
            print ("\nByte number " + str(invalid_byte) + " belongs to extended ASCII")
            print ("\nIn: " + element)

    



    def _Get_Body(self):
        """
        extracts the body of the email
        """
        if self.data_mail.is_multipart():
            for part in self.data_mail.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))
                # skip any text/plain (txt) attachments
                if ctype == 'text/plain' and 'attachment' not in cdispo:
                    self.body = part.get_payload(decode=True)  # decode Unicode
                    break
            if self.show_details == True:    
                print ("\nBODY:\n")
            # not multipart - i.e. plain text, no attachments
        else:
            self.body = self.data_mail.get_payload(decode=True)
        



    def _Get_Headers(self):
        """
        extracts all headers found in the file and verifies that they are correct
        """
        var_aux = False
        var_bound = True
        var_bound_init = False
        var_bound_end = False
        var_content = False
        parser = email.parser.HeaderParser()
        self.headers = parser.parsestr(self.data_mail.as_string())
        for element, length in self.data_str:

            left_text_header = element.partition(" ")[0]
            left_text_header_p = element.partition(":")[0]
            self.counter_read = self.counter_read + 1

            try:
                _ = element.decode('ascii')
            except UnicodeDecodeError:
                self.var_valid = False
                self._InvalidByteExtendedASCII(element,self.count_bytes)
                self.list_invalid.append(element)
                if self.show_details == True:
                    print ("\nLine has ASCII characters extended in: " + element)

            if "Content-Type: multipart" in element:
                if "boundary=" in element:
                    self.boundary_mail = element.partition("=")[2]
                    self.boundary_mail = self.boundary_mail[1:-1]
                    var_bound = True

            if (left_text_header[2:] == self.boundary_mail) and (var_bound == True):
                var_content = True
            
            if (left_text_header[2:] == self.boundary_mail + "--"):# and (var_bound == True):
                var_content = False
                var_bound_end = True                

            if "Content-Disposition: attachment" in element:
                if "filename=" in element:
                    self.filename = element.partition("=")[2]
                    self.filename = self.filename[1:-1]        
                    
            if (':' in left_text_header) and (left_text_header[:-1] in self.valid_headers_list):
                var_aux = False
            elif not left_text_header:
                var_aux = False
            elif (':' in element):
                self.list_invalid.append(element)
                self.var_valid = False
                left_text_invalid = element.partition(":")[0]
                if ' ' in left_text_invalid:
                    self._InvalidByteWSHeader(left_text_invalid,self.count_bytes)            

            self.count_bytes = self.count_bytes + length  # +CR LF 
            
        # endfor
              
        if self.var_valid == True:
            if self.show_details == True:
                print ("\nHEADERS:\n")
                for h in self.headers.items():
                    print (h)
                    
        if var_bound == False:
            self.var_valid = False
            if self.show_details == True:
                print ("\n No boundary detected\n")
            
        if var_bound == True and var_bound_end == False:
            self.var_valid = False
            if self.show_details == True:
                print ("\n No boundary ends detected\n")
        


    
    def Validate(self,fd):
        """
        Validates a file-like object to determine if its a valid EML file.

        :param fd: file descriptor (file-like)
        :return: True on valid EML, False otherwise (bool)
        """
        self._Cleanup()
        var_aux = False

        if type(fd) == file:
            file_data = fd.read()
            fd.seek(0)
            self.data_str = [(l, len(k)) for l, k in zip(file_data.splitlines(), file_data.splitlines(True))]
            self.data_mail = email.message_from_file(fd)
            
        elif type(fd) == str:
            self.data_mail = fd
        else:
            raise Exception("Argument must be either a file or a string.")
        self._Get_Headers()
        self._Get_Body()
        for h in self.headers.items():
            if h[0] in self.valid_headers_list:
                self.objects_found.append(h[0])
                var_aux = True
            else:
                self.list_invalid.append(h)
                self.var_valid = False
        # endfor
        
        if self.var_valid == True:
            print ("\nValid EML")
            self.is_valid = True
            if self.show_details == True:
                self.show_details = False
                     
        elif self.var_valid == False:
            print ("\nInvalid EML\n")
            self.is_valid = False
            if self.show_details == True:
                self.show_details = False
                print ("Invalid List Elements: \n")
                print (self.list_invalid)
                
          
       

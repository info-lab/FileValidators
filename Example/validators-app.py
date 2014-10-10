#coding = utf-8
import datetime
import os
import time

import FileValidators as validators

from sys import argv
#todo:
#   * argparse
#   * translate
#   * improve code


def microtime():
    dt = datetime.datetime.now()
    return time.mktime(dt.timetuple()) + dt.microsecond / 1000000.0

if len(argv) != 2:
    print "Error en la llamada al programa. Uso:"
    print "    python %s [path]" % argv[0]
    print "Donde [path] es la ruta del directorio donde estan los archivos que desea validar."
    exit()

scriptname, path = argv
t1 = microtime()
counter_valid = 0
counter_invalid = 0
if os.path.exists(path):
    validators_dict = {
        '.jpg': validators.JPGValidator(),
        '.png': validators.PNGValidator(),
        '.doc': validators.MSOLEValidator(),
        '.xls': validators.MSOLEValidator(),
        '.ppt': validators.MSOLEValidator(),
        '.zip': validators.ZIPValidator(),
    }
    for root, dirs, files in os.walk(path):
        for filename in files:
            extension = os.path.splitext(filename)[1]
            if extension in validators_dict.keys():
                file = open(os.path.join(root, filename), "rb", 1048576)
                valid = validators_dict[extension].Validate(file)
                file.close()
                if valid:
                    print "%s|valido" % filename
                    #print validators_dict[extension].getStatus()
                    counter_valid += 1
                else:
                    print "%s|no valido" % filename
                    #print validators_dict[extension].getStatus()
                    counter_invalid += 1
        #for file
    #for root
else:
    print "El directorio especificado no existe."
print "\nArchivos validos: %d" % counter_valid
print "Archivos invalidos: %d" % counter_invalid
print "Tiempo: %d segundos" % (microtime() - t1)
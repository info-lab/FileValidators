# coding=utf-8
import array
import struct
import binascii
import zlib

""" 
Overall .ZIP file format:

      [local file header 1]
      [encryption header 1]
      [file data 1]
      [data descriptor 1]
      . 
      .
      .
      [local file header n]
      [encryption header n]
      [file data n]
      [data descriptor n]
      [archive decryption header] 
      [archive extra data record] 
      [central directory header 1]
      .
      .
      .
      [central directory header n]
      [zip64 end of central directory record]
      [zip64 end of central directory locator] 
      [end of central directory record]
"""

class ZIPValidator2(object):
	
    # Here are some struct module formats for reading headers
    structEndArchive = "<4s4H2lH"     # 9 items, end of archive, 22 bytes
    stringEndArchive = "PK\005\006"   # magic number for end of archive record
    structCentralDir = "<4s4B4H3l5H2l"# 19 items, central directory, 46 bytes
    stringCentralDir = "PK\001\002"   # magic number for central directory
    structFileHeader = "<4s2B4H3l2H"  # 12 items, file header record, 30 bytes
    stringFileHeader = "PK\003\004"   # magic number for file header
    """ Class that validates an object to determine if it is a valid ZIP file. """
    optimistic = 1

    def __init__(self, maximum_chunk_length = (1024 * 1024) * 20):
        self.is_valid = False
        self.eof = False
        self.bytes_last_valid = -1
        self.max_chunk_length = maximum_chunk_length
        self._chunksize = 128
        
        
    def is_zipfile(filename):
		"""Quickly see if file is a ZIP file by checking the magic number.

		Will not accept a ZIP archive with an ending comment.    """
		try:
			fpin = open(filename, "rb")
			fpin.seek(-22, 2)               # Seek to end-of-file record
			endrec = fpin.read()
			fpin.close()
			if endrec[0:4] == "PK\005\006" and endrec[-2:] == "\000\000":
				return 1    # file has correct magic number
		except IOError:
			pass
        
    def GetStatus(self):
        return (self.is_valid, self.eof, self.bytes_last_valid)

    def Dump(n, a = 0): 
	s = '%x' % int(a)
	if len(s) & 1:
	    s = '0' + s
	return s.decode('hex')
	
	def gradeOptimistic(self,opt = 0):
		
		if opt == -1:
			# SuperOptimica
			self.optimistic = -1
		if opt == 1:
			# Pesimista
			self.optimistic = 1
		else:
			# Optimica
			self.optimistic = 0

    def Validate(self, file):
	""" Local File header  x04034b50 -- Archive extra data record 0x08064b50 -- File header 0x02014b50"""
	""" Digital signature   0x05054b50 -- Zip64 end of central directory record  0x06064b50 """
	""" Zip64 end of central directory locator 0x07064b50 -- End of central directory 0x06054b50"""
        valid_markers = {'\x04\x03\x4b\x50','\x08\x06\x4b\x50','\x02\x01\x4b\x50',
			'\x05\x05\x4b\x50', '\x06\x06\x4b\x50','\x07\x06\x4b\x50'
			'\x06\x05\x4b\x50'}
	""" Header
	 version needed to extract       2 bytes
	 general purpose bit flag        2 bytes
         compression method              2 bytes
         last mod file time              2 bytes
         last mod file date              2 bytes
         crc-32                          4 bytes # crc del objeto descomprimido.
         compressed size                 4 bytes
         uncompressed size               4 bytes	
         file name length                2 bytes
    	 extra field length              2 bytes
    	 
    	 
	 other info ...
	"""
	
        self.eof = False
        self.bytes_last_valid = 0
	current_marker, = struct.unpack("<4s",file.read(4))
	bytes_read = 4
	cabezeraZIP = header()
	if (cabezeraZIP.is_header(current_marker)):
	    self.is_valid = True
	else:
	    self.is_valid = False
	file_tell = 0
	bingo = 0
	bytes = "%s%s" % (current_marker,file.read(self._chunksize))

	bytes_last_valid = bytes_read
	while (not(self.eof) and not(cabezeraZIP.estado == cabezeraZIP.finEstado)):
		self.eof = len(bytes) < self._chunksize
                adjust_offset = 0
                seek_marker = "PK"  in bytes

		#print "largo %d" % (file_tell)
                if (seek_marker):
		    pos = bytes.find("PK")
		    adjust_offset += pos
		    print "En busca de un marcador %d" % (pos)
		    #@TODO Verificar que no me voy de archivo
		    file.seek(file_tell + adjust_offset)
		    potencial_marker = file.read(4)
		    self.eof = False
		    if (cabezeraZIP.is_header(potencial_marker)):
				bingo = bingo + 1
				self.optimistic ==1
				if (self.optimistic>=0):
					print "Entre .."
					if self.optimistic==0:
					    op = True
					else:
					    op = False
					layout = layoutFactory(cabezeraZIP.estado,op).getObject()
					if  not(layout.is_valid(file)):
						# volvemos al marcador y lo saltamos.
						print "No es supervalido lo dijo Layout"
						file.seek(file_tell + adjust_offset+4)
						# si es super optimistico deberiamos tomar como valido este marcador.
					else:	
						print "Es supervalido lo dijo Layout"
						self.bytes_last_valid = (file_tell + adjust_offset)		
				else:
				    print "Lo anterior es valido porque este es una cabecera"
				    self.bytes_last_valid = (file_tell + adjust_offset)							
				print "bingo -- pos %d -- Tam Cab %d" % (self.bytes_last_valid, layout.getHeaderSize())
		    else:
				print "falsa alarma" 
		file_tell = file.tell()
		bytes = file.read(self._chunksize)
		print "Cabezera estado %s eof %s fin de estado %s" % (cabezeraZIP.estado,self.eof,cabezeraZIP.finEstado)
		    

	file.seek(-2,2) # move the cursor to the end of the file
	bytes = file.read(2)
	self.is_valid = (cabezeraZIP.estado == cabezeraZIP.finEstado) and (bytes[-2:] == "\000\000")
	if (self.is_valid):
		file.seek(0,2) # move the cursor to the end of the file
	        size = file.tell()
    		self.bytes_last_valid = size
		print "Es valido"
	else:
		print "No es valido"
	print "Finalize.. Tamanio valido %d, cabezeras %d fin de archivo %d" % (self.bytes_last_valid, bingo, self.eof)
	return self.is_valid



class header:
	stringEndArchive = "PK\005\006"   # magic number for end of archive record
	stringCentralDir = "PK\001\002"   # magic number for central directory
	stringFileHeader = "PK\003\004"   # magic number for file header
	
	
	losEstados = { 0 : [stringFileHeader], 1 : [stringFileHeader, stringCentralDir], 2 : [stringCentralDir, stringEndArchive]  }
	elEstado = { stringFileHeader: 1, stringCentralDir :2 , stringEndArchive :3}
	finEstado = 3

	def __init__(self):
	    self.estado=0

	def is_header(self,data):
	    """@TODO mejorar no es una maquina de estado perfecta...
		si  el end llega primero no funciona..
	    """
	    print "Data: %s" % (data)
	    if (data in self.losEstados[self.estado]):
		if ((self.estado+1) == self.elEstado[data]):
		    self.estado = self.elEstado[data];
		    print "Cambio de estado %d" % (self.estado)
		return True
	    else:
		return False
	
	def header(self,data):
	    return True


class layoutFactory:

	def __init__(self, layout, opt = True):
		self.optimistic = opt
		self.layout = layout
		if layout == 2:
			self.object = centralDir(opt)
		elif layout == 3:
			self.object = endArchive(opt)
		else:
			self.object = localFile(opt)			

	def getObject(self):
		return self.object


class endArchive:
	# Si contar la parte variable
	headerSize = 22
	structEndArchive = "<4s4H2lH"     # 9 items, end of archive, 22 bytes
	stringEndArchive = "PK\005\006"   # magic number for end of archive record
 
	def __init__(self, opt = True):
		self.optimistic = opt

	def getOffset(self):
		return 0

	def getHeaderSize(self):
		return self.headerSize

	def getStruct(self):
		return self.structEndArchive

	def setHeaderSize(self,size):
		self.headerSize = size 

	def is_valid(self, file):
		file.seek(-4,1) # Retrocedo 4 que es la cabezera
		cabezera = struct.unpack(self.getStruct(),file.read(self.getHeaderSize()))
		return True

class centralDir:
	# Si contar la parte variable
	headerSize = 46
   	structCentralDir = "<4s4B4H3l5H2l"# 19 items, central directory, 46 bytes
	stringCentralDir = "PK\001\002"   # magic number for central directory

	def __init__(self, opt = True):
		self.optimistic = opt

	def getOffset(self):
		return 0

	def getHeaderSize(self):
		return self.headerSize

	def setHeaderSize(self,size):
		self.headerSize = size

	def getStruct(self):
		return self.structCentralDir 
	
	def is_valid(self, file):
		file.seek(-4,1) # Retrocedo 4 que es la cabezera
		cabezera = struct.unpack(self.getStruct(),file.read(self.getHeaderSize()))
				
		
		return True

class localFile:

	# indexes of entries in the local file header structure
	_FH_SIGNATURE = 0
	_FH_EXTRACT_VERSION = 1
	_FH_EXTRACT_SYSTEM = 2                  # is this meaningful?
	_FH_GENERAL_PURPOSE_FLAG_BITS = 3
	_FH_COMPRESSION_METHOD = 4
	_FH_LAST_MOD_TIME = 5
	_FH_LAST_MOD_DATE = 6
	_FH_CRC = 7
	_FH_COMPRESSED_SIZE = 8
	_FH_UNCOMPRESSED_SIZE = 9
	_FH_FILENAME_LENGTH = 10
	_FH_EXTRA_FIELD_LENGTH = 11
	# Si contar la parte variable
	headerSize = 30
	structFileHeader = "<4s2B4H3l2H"  # 12 items, file header record, 30 bytes
	stringFileHeader = "PK\003\004"   # magic number for file header
	offset = 0

	# constants for Zip file compression methods
	ZIP_STORED = 0
	ZIP_DEFLATED = 8

	def __init__(self, opt = True):
		self.optimistic = opt


	def getOffset(self):
		return self.offset
	
	def setOffset(self,size):
		self.offset = size

	def getHeaderSize(self):
		return self.headerSize

	def setHeaderSize(self,size):
		self.headerSize = size 

	def getStruct(self):
		return self.structFileHeader 
	
	def is_valid(self, file):
		ZIP_STORED = 0
		ZIP_DEFLATED = 8
		file.seek(-4,1) # Retrocedo 4 que es la cabezera
		cabezera = struct.unpack(self.getStruct(),file.read(self.getHeaderSize()))
		#@TODO ver si los datos estan al fondo
		sizeHeader = self.getHeaderSize() + cabezera[self._FH_FILENAME_LENGTH] + cabezera [self._FH_EXTRA_FIELD_LENGTH]
		self.setHeaderSize(sizeHeader)
		sizeBody = cabezera [self._FH_COMPRESSED_SIZE]
		print "Largo del Archivo comprimido %d" % (sizeBody)
		self.setOffset(sizeHeader + sizeBody)
		nombre = file.read(cabezera[self._FH_FILENAME_LENGTH])
		extra =  file.read(cabezera[self._FH_EXTRA_FIELD_LENGTH])
		bytes = file.read(sizeBody)
		eloff = file.tell()
		if (cabezera[self._FH_COMPRESSION_METHOD] == ZIP_DEFLATED):
		    bytes = self.decompressZlib(bytes)
		if (self.optimistic):
			isTrue = True
			print "Es valido en forma optimista, %s, offset = %d" % (nombre, eloff)
		else:
			print "Es valido en forma pesimista, %s , offset = %d" % (nombre,eloff)
			if ((cabezera[self._FH_COMPRESSION_METHOD] == ZIP_DEFLATED) or (cabezera[self._FH_COMPRESSION_METHOD] ==  ZIP_STORED)):
			    # Verificar CRC
			    crc = binascii.crc32(bytes)
			    if crc == cabezera[self._FH_CRC]:
				print "CRC OK"
				isTrue = True
			    else: 
				print "NOT CRC OK"
				isTrue = False
			else:
			    #Si deconozco la compresion busco la cabezera siguiente
			    inicioCab = file.read(2)
			    file.seek(-2,1) # Dos para atras
			    if (inicioCab == "PK"):
				isTrue = True
			    else: 
				isTrue = False

		
		return isTrue

	def decompressZlib(self,bytes):
	    dc = zlib.decompressobj(-15)
            bytes = dc.decompress(bytes)
            # need to feed in unused pad byte so that zlib won't choke
            ex = dc.decompress('Z') + dc.flush()
            if ex:
                bytes = bytes + ex
		
	    return bytes


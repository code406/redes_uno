from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
import math
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Valor inicial para el IPID
IPID = 0
#Valor de ToS por defecto
DEFAULT_TOS = 0
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
#Valor de TTL por defecto
DEFAULT_TTL = 64
#Protocolos
ICMP = 1
TCP = 6
UDP = 17


def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i]
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]

    s.close()

    return mtu

def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    #print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]


def process_IP_datagram(us,header,data,srcMac):
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum sobre los bytes de la cabecera IP
                    -Comprobar que el resultado del checksum es 0. Si es distinto el datagrama se deja de procesar
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón
                    pasando los datos (payload) contenidos en el datagrama IP.

        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    #TODO:
    version = data[0] & 0xF0
    ihl = (data[0] & 0x0F)*4
    typeOfService = data[1]
    totalLength = data[2:4]
    IPID_read = data[4:6] #se llama asi para no destrozar la variable global IPID
    flagBit1 = data[6] & 0x01
    flagDF = data[6] & 0x02
    flagMF = data[6] & 0x03
    offset = (data[6] & 0xF8) + data[7]
    timeToLive = data[8]
    protocol = data[9]
    headerChecksum = data[10:12]
    ipOrigen = data[12:16]
    ipDestino = data[16:20]
    options = data[20:]

    print("[process_IP_datagram] Extracted all fields from datagram")

    #if chksum(data) != 0: 
    #    print("[process_IP_datagram] Checksum != 0. Returning")
    #    return
    #OJO: Dice "Analizar los bits de de MF y el offset". Que analizamos de mf??
    #OJO: Dice "para obtener el valor real de offset se debe multiplicar por 8"
    #if offset != 0: return #
    logging.debug(ihl)
    #logging.debug(struct.unpack('!H', totalLength)[0])
    logging.debug(IPID_read)
    logging.debug(flagDF)
    logging.debug(flagMF)
    logging.debug(offset*8)
    logging.debug(ipOrigen)
    logging.debug(ipDestino)
    logging.debug(protocol)

    if protocols.get(protocol):
        payload = data[ihl:struct.unpack('!H', totalLength)[0]] #ihl->totalength
        protocols[protocol](us, header, payload, ipOrigen)
    else:
        print("[process_IP_datagram] No function registered for protocol", protocol)


def registerIPProtocol(callback,protocol):
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla
            (diccionario) de protocolos de nivel superior dicha asociación.
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra
            llamada process_ICMP_message asocaida al valor de protocolo 1.
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado.
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno
    '''
    #TODO:
    if callback != None and protocol in [ICMP, TCP, UDP]:
        protocols[protocol] = callback


def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW,ipOpts
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
    #TODO:
    if initARP(interface) != True:
        return False
    #Guardando en variables globales. OJO: FUNCIONES DEVUELVEN ENTEROS?
    myIP = getIP(interface) #
    MTU = getMTU(interface)
    netmask = getNetmask(interface) #
    defaultGW = getDefaultGW(interface) #
    if myIP == None or MTU == None or netmask == None or defaultGW == None:
        return False

    ipOpts = opts
    registerCallback(process_IP_datagram, bytes([0x08,0x00]))
    print("[initIP] IP initialized succesfully")
    return True


def sendIPDatagram(dstIP,data,protocol):
    global IPID, MTU, ipOpts, netmask, defaultGW
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera en la posición correcta
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas:
                    -Si la dirección IP destino está en mi subred:
                        -Realizar una petición ARP para obtener la MAC asociada a dstIP y usar dicha MAC
                    -Si la dirección IP destino NO está en mi subred:
                        -Realizar una petición ARP para obtener la MAC asociada al gateway por defecto y usar dicha MAC
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no

    '''
    #TODO:
    print("[sendIPDatagram] Sending frame with protocol", protocol, "to", '{:12}'.format(socket.inet_ntoa(struct.pack('!I',dstIP))))

    len_opts = len(ipOpts) if ipOpts else 0
    if len_opts % 4 != 0:
        ipOpts = ipOpts + (4 - (len_opts % 4)) * [0x00]
        len_opts = len(ipOpts)

    header_len = 20 + len_opts
    max_len_datos_utiles = (MTU-header_len) - (MTU-header_len)%8
    num_fragmentos = math.ceil(len(data) / max_len_datos_utiles)
    last_frag_len = len(data) - (max_len_datos_utiles * (num_fragmentos-1))
    totalLength = max_len_datos_utiles + header_len
    print(num_fragmentos, max_len_datos_utiles, header_len)

    mf_bits = 0b00100000
    for i in range (num_fragmentos):
        print("\n------------------\nVUELTA DEL FOR----------------------\n")
        header = bytearray()
        ini = i*max_len_datos_utiles
        fin = (i+1)*max_len_datos_utiles #TODO: revisar este +1 (es para el ini:fin que no llega a fin)
        if i == num_fragmentos-1:
            mf_bits = 0
            fin = ini + last_frag_len
            totalLength = last_frag_len + header_len
        header += bytes(struct.pack('B', 0b01000000 + int(header_len/4)))#byte con 04 en 4 bits y hlen reducido en otros 4
        header += bytes([0x00])#type of service always 0
        header += bytes(struct.pack('!H', totalLength))
        header += bytes(struct.pack('!H', IPID))
        header += bytes(struct.pack('B', mf_bits + int(ini/256)))
        header += bytes(struct.pack('B', ini%256))
        header += bytes(struct.pack('B', 64))
        header += bytes(struct.pack('B', protocol))
        header += bytes(struct.pack('!H', 0)) #checksum a 0 ahora
        header += bytes(struct.pack('!I', myIP))
        header += bytes(struct.pack('!I', dstIP))
        if ipOpts: 
            header += ipOpts
        print("ELHEADER:", header)
        header[10:12] = bytes(struct.pack('!H', chksum(header))) #calculamos el checksum
        header += data[ini:fin]
        print("HEADERLEN: ", len(header))
        if (netmask & myIP) == (netmask & dstIP):
            print("[sendIPDatagram] Seems", '{:12}'.format(socket.inet_ntoa(struct.pack('!I',dstIP)) + " is in my network."))
            sendEthernetFrame(header, len(header), bytes([0x08, 0x00]), ARPResolution(dstIP))
        else:
            print("[sendIPDatagram] Seems", '{:12}'.format(socket.inet_ntoa(struct.pack('!I',dstIP)) + " is NOT in my network."))
            sendEthernetFrame(header, len(header), bytes([0x08, 0x00]), ARPResolution(defaultGW))

    IPID += 1
    return True

'''
    arp.py
    Implementación del protocolo ARP y funciones auxiliares que permiten realizar resoluciones de direcciones IP.
    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''



from ethernet import *
import logging
import socket
import struct
import fcntl
import time
import binascii
from threading import Lock
from expiringdict import ExpiringDict

#Semáforo global
globalLock =Lock()
#Dirección de difusión (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Cabecera ARP común a peticiones y respuestas. Específica para la combinación Ethernet/IP
ARPHeader = bytes([0x00,0x01,0x08,0x00,0x06,0x04])
#longitud (en bytes) de la cabecera común ARP
ARP_HLEN = 6

#Variable que alamacenará que dirección IP se está intentando resolver
requestedIP = None
#Variable que alamacenará que dirección MAC resuelta o None si no se ha podido obtener
resolvedMAC = None
#Variable que alamacenará True mientras estemos esperando una respuesta ARP
awaitingResponse = False
#Variable que alamacenará My IP
myIP = None
#Variable para proteger la caché
cacheLock = Lock()
#Caché de ARP. Es un diccionario similar al estándar de Python solo que eliminará las entradas a los 10 segundos
cache = ExpiringDict(max_len=100, max_age_seconds=10)



def getIP(interface):
    '''
        Nombre: getIP
        Descripción: Esta función obtiene la dirección IP asociada a una interfaz. Esta funció NO debe ser modificada
        Argumentos:
            -interface: nombre de la interfaz
        Retorno: Entero de 32 bits con la dirección IP de la interfaz
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]

def printCache():
    '''
        Nombre: printCache
        Descripción: Esta función imprime la caché ARP
        Argumentos: Ninguno
        Retorno: Ninguno
    '''
    print('{:>12}\t\t{:>12}'.format('IP','MAC'))
    with cacheLock:
        for k in cache:
            if k in cache:
                print ('{:>12}\t\t{:>12}'.format(socket.inet_ntoa(struct.pack('!I',k)),':'.join(['{:02X}'.format(b) for b in cache[k]])))



def processARPRequest(data,MAC):
    '''HECHO
        Nombre: processARPRequest
        Decripción: Esta función procesa una petición ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la MAC origen contenida en la petición ARP
            -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
            -Extraer la IP origen contenida en la petición ARP
            -Extraer la IP destino contenida en la petición ARP
            -Comprobar si la IP destino de la petición ARP es la propia IP:
                -Si no es la propia IP retornar
                -Si es la propia IP:
                    -Construir una respuesta ARP llamando a createARPReply (descripción más adelante)
                    -Enviar la respuesta ARP usando el nivel Ethernet (sendEthernetFrame)
        Argumentos:
            -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
            -MAC: dirección MAC origen extraída por el nivel Ethernet
        Retorno: Ninguno
    '''
    #TODO implementar aquí
    global myIP
    #print("[processARPRequest] Processing ARP Request")
    macOrigen = data[0:6]

    if macOrigen != MAC:
        #print("[processARPRequest] ARP MAC not matching Ethernet MAC")
        return

    ipOrigen = data[6:10]
    ipDestino = data[16:20]

    if ipDestino != struct.pack('!I',myIP):
        #print("[processARPRequest] This request is not for me")
        return

    #print("[processARPRequest] Calling createARPReply")
    reply = createARPReply(ipOrigen, macOrigen)
    sendEthernetFrame(reply,len(reply), bytes([0x08,0x06]), macOrigen)

def processARPReply(data,MAC):
    ''' HECHO
        Nombre: processARPReply
        Decripción: Esta función procesa una respuesta ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la MAC origen contenida en la petición ARP
            -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
            -Extraer la IP origen contenida en la petición ARP
            -Extraer la MAC destino contenida en la petición ARP
            -Extraer la IP destino contenida en la petición ARP
            -Comprobar si la IP destino de la petición ARP es la propia IP:
                -Si no es la propia IP retornar
                -Si es la propia IP:
                    -Comprobar si la IP origen se corresponde con la solicitada (requestedIP). Si no se corresponde retornar
                    -Copiar la MAC origen a la variable global resolvedMAC
                    -Añadir a la caché ARP la asociación MAC/IP.
                    -Cambiar el valor de la variable awaitingResponse a False
                    -Cambiar el valor de la variable requestedIP a None
        Las variables globales (requestedIP, awaitingResponse y resolvedMAC) son accedidas concurrentemente por la función ARPResolution y deben ser protegidas mediante un Lock.
        Argumentos:
            -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
            -MAC: dirección MAC origen extraída por el nivel Ethernet
        Retorno: Ninguno
    '''
    global requestedIP,resolvedMAC,awaitingResponse,cache
    #TODO implementar aquí
    #print("[processARPReply] Processing ARP Reply")
    macOrigen = data[0:6]

    if macOrigen != MAC:
        #print("[processARPReply] ARP MAC not matching Ethernet MAC")
        return

    ipOrigen = data[6:10]
    macDestino = data[10:16]
    ipDestino = data[16:20]

    #print("[processARPReply] Reply read: ipDestino:", str(ipDestino), "myIP:", str(struct.pack('!I',myIP)))
    if ipDestino != struct.pack('!I',myIP):
        #print("[processARPReply] This reply is not for me")
        return

    with globalLock:
        if struct.unpack('!I',ipOrigen)[0] != requestedIP:
            return
        #print("[processARPReply] Saving resolved MAC in global var")
        resolvedMAC = macOrigen
        awaitingResponse = False
        requestedIP = None

    with cacheLock:
        cachekey = struct.unpack('!I',ipOrigen)[0]
        #print("[processARPReply] Adding MAC for key", cachekey, "to cache")
        cache[cachekey] = macOrigen

def createARPRequest(ip):
    '''HECHO
        Nombre: createARPRequest
        Descripción: Esta función construye una petición ARP y devuelve la trama con el contenido.
        Argumentos:
            -ip: dirección a resolver
        Retorno: Bytes con el contenido de la trama de petición ARP
    '''
    global myMAC,myIP, ARPHeader
    #print("[createARPRequest] Creating Request")
    frame = bytes()
    frame += ARPHeader
    frame += bytes([0x00,0x01])
    frame += myMAC
    frame += struct.pack('!I',myIP)
    frame += bytes([0x00,0x00,0x00,0x00,0x00,0x00])
    frame += struct.pack('!I',ip)

    #print("\nFRAME EN REQUEST: " + str(frame))
    return frame


def createARPReply(IP,MAC):
    '''HECHO
        Nombre: createARPReply
        Descripción: Esta función construye una respuesta ARP y devuelve la trama con el contenido.
        Argumentos:
            -IP: dirección IP a la que contestar
            -MAC: dirección MAC a la que contestar
        Retorno: Bytes con el contenido de la trama de petición ARP
    '''
    global myMAC,myIP, ARPHeader
    #print("[createARPReply] Creating Reply")
    frame = bytes()
    frame += ARPHeader
    frame += bytes([0x00,0x02])
    frame += myMAC
    frame += struct.pack('!I',myIP)
    frame += MAC
    frame += IP

    #print("\nFRAME EN REPLY: " + str(frame))
    return frame


def process_arp_frame(us,header,data,srcMac):
    ''' HECHO
        Nombre: process_arp_frame
        Descripción: Esta función procesa las tramas ARP.
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype 0x0806 (si ha sido registrada en initARP).
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer la cabecera común de ARP (6 primeros bytes) y comprobar que es correcta
                -Extraer el campo opcode
                -Si opcode es 0x0001 (Request) llamar a processARPRequest (ver descripción más adelante)
                -Si opcode es 0x0002 (Reply) llamar a processARPReply (ver descripción más adelante)
                -Si es otro opcode retornar de la función
                -En caso de que no exista retornar
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ARP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    #TODO implementar aquí
    cabecera = data[0:6]
    opCode = data[6:8]
    dataNew = data[8:]

    if opCode == bytes([0x00,0x01]):
        #print("[process_arp_frame] opCode 0x0001. Calling processARPRequest")
        processARPRequest(dataNew, srcMac)
    elif opCode == bytes([0x00,0x02]):
        #print("[process_arp_frame] opCode 0x0002. Calling processARPReply")
        processARPReply(dataNew, srcMac)
    else:
        #print("[process_arp_frame] UNKNOWN OPCODE IN FRAME" + str(opCode))
        return

def initARP(interface):
    ''' HECHO
        Nombre: initARP
        Descripción: Esta función construirá inicializará el nivel ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar la función del callback process_arp_frame con el Ethertype 0x0806
            -Obtener y almacenar la dirección MAC e IP asociadas a la interfaz especificada
            -Realizar una petición ARP gratuita y comprobar si la IP propia ya está asignada. En caso positivo se debe devolver error.
            -Marcar la variable de nivel ARP inicializado a True
    '''
    global myIP,myMAC,arpInitialized

    #TODO implementar aquí
    print("[init_arp] Initializing ARP")
    arpInitialized = False
    registerCallback(process_arp_frame,  bytes([0x08,0x06]))
    myIP = getIP(interface)
    myMAC = getHwAddr(interface) #myMAC = bytes(binascii.hexlify(getHwAddr(interface)))

    if ARPResolution(myIP) != None:
        print("[init_arp] Someone has my IP!!")
        return False

    print("[init_arp] ARP initialized succesfully")
    arpInitialized = True
    return True

def ARPResolution(ip):
    '''
        Nombre: ARPResolution
        Descripción: Esta función intenta realizar una resolución ARP para una IP dada y devuelve la dirección MAC asociada a dicha IP
            o None en caso de que no haya recibido respuesta. Esta función debe realizar, al menos, las siguientes tareas:
                -Comprobar si la IP solicitada existe en la caché:
                -Si está en caché devolver la información de la caché
                -Si no está en la caché:
                    -Construir una petición ARP llamando a la función createARPRequest (descripción más adelante)
                    -Enviar dicha petición
                    -Comprobar si se ha recibido respuesta o no:
                        -Si no se ha recibido respuesta reenviar la petición hasta un máximo de 3 veces. Si no se recibe respuesta devolver None
                        -Si se ha recibido respuesta devolver la dirección MAC
            Esta función necesitará comunicarse con el la función de recepción (para comprobar si hay respuesta y la respuesta en sí) mediante 3 variables globales:
                -awaitingResponse: indica si está True que se espera respuesta. Si está a False quiere decir que se ha recibido respuesta
                -requestedIP: contiene la IP por la que se está preguntando
                -resolvedMAC: contiene la dirección MAC resuelta (en caso de que awaitingResponse) sea False.
            Como estas variables globales se leen y escriben concurrentemente deben ser protegidas con un Lock
    '''
    global requestedIP,awaitingResponse,resolvedMAC
    #TODO implementar aquí

    print("[ARPResolution] Who has", '{:12}'.format(socket.inet_ntoa(struct.pack('!I',ip)) + "?"))
    with cacheLock:
        mac = cache.get(ip)
        if mac != None:
            print("[ARPResolution] Mac was cached:", ':'.join(['{:02X}'.format(b) for b in mac]))
            return mac

    with globalLock:
        awaitingResponse = True
        requestedIP = ip

    data = createARPRequest(ip)
    sendEthernetFrame(data, len(data), bytes([0x08,0x06]), broadcastAddr)

    for i in range(3):
        time.sleep(0.5)
        with globalLock:
            if awaitingResponse == True and requestedIP != None:
                data = createARPRequest(ip)
                sendEthernetFrame(data, len(data), bytes([0x08,0x06]), broadcastAddr)
            else:
                print("[ARPResolution] Resolved MAC:", ':'.join(['{:02X}'.format(b) for b in resolvedMAC]))
                return resolvedMAC
    print("[ARPResolution] MAC unresolved")
    return None

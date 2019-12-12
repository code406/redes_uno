from ip import *
from threading import Lock
import struct

ICMP_PROTO = 1

ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

timeLock = Lock()
icmp_send_times = {}

def process_ICMP_message(us,header,data,srcIp):
    '''
        Nombre: process_ICMP_message
        Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
        un 1 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Calcular el checksum de ICMP:
                -Si es distinto de 0 el checksum es incorrecto y se deja de procesar el mensaje
            -Extraer campos tipo y código de la cabecera ICMP
            -Loggear (con logging.debug) el valor de tipo y código
            -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
                -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
                los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
                -Enviar el mensaje usando la función sendICMPMessage
            -Si el tipo es ICMP_ECHO_REPLY_TYPE:
                -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
                contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
                -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
                -Mostrar por pantalla la resta. Este valor será una estimación del RTT
            -Si es otro tipo:
                -No hacer nada

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del mensaje ICMP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno

    '''
    #HACER
    print("[process_ICMP_message] Processing ICMP message with data", data)
    checksum = data[2:4]
    #if checksum != 0:
    #    return
    type = data[0]
    code = data[1]
    logging.debug(type)
    logging.debug(code)


    identifier = struct.unpack('!H', data[4:6])[0]
    sequenceNumber = struct.unpack('!H', data[6:8])[0]
    if type == ICMP_ECHO_REQUEST_TYPE:
        print("[process_ICMP_message] Received an ICMP_ECHO_REQUEST")
        #print("SRC IP:", srcIp, "identifier:", identifier, "SEQ:", sequenceNumber)
        sendICMPMessage(data[8:], ICMP_ECHO_REPLY_TYPE, code, identifier, sequenceNumber, struct.unpack('!I', srcIp)[0])

    if type == ICMP_ECHO_REPLY_TYPE:
        print("[process_ICMP_message] Received an ICMP_ECHO_REPLY")
        #print("SRC IP:", srcIp, "identifier:", identifier, "SEQ:", sequenceNumber)
        with timeLock:
            time = header.ts.tv_sec - icmp_send_times[struct.unpack('!I', srcIp)[0] + identifier + sequenceNumber]
        print("ESTIMACION DE RTT: {}".format(time))


def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):
    '''
        Nombre: sendICMPMessage
        Descripción: Esta función construye un mensaje ICMP y lo envía.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
                -Construir la cabecera ICMP
                -Añadir los datos al mensaje ICMP
                -Calcular el checksum y añadirlo al mensaje donde corresponda
                -Si type es ICMP_ECHO_REQUEST_TYPE
                    -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                    usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                    -Se debe proteger al acceso al diccionario usando la variable timeLock

                -Llamar a sendIPDatagram para enviar el mensaje ICMP

            -Si no:
                -Tipo no soportado. Se devuelve False

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
            -type: valor del campo tipo de ICMP
            -code: valor del campo code de ICMP
            -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
            -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
            -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
        Retorno: True o False en función de si se ha enviado el mensaje correctamente o no

    '''
    #HACER
    if type != ICMP_ECHO_REQUEST_TYPE and type != ICMP_ECHO_REPLY_TYPE:
        return False

    message = bytearray()
    message += bytes(struct.pack('B', type))
    message += bytes(struct.pack('B', code))
    message += bytes([0x00,0x00])
    message += bytes(struct.pack('!H', icmp_id))
    message += bytes(struct.pack('!H', icmp_seqnum))
    message += data

    #SEEMS CHKSUM HAS TO BE LITTLE ENDIAN SO THAT WIRESHARK VALIDATES IT. WONDER WHY
    message[2] = bytes(struct.pack('!H', chksum(message)))[1]
    message[3] = bytes(struct.pack('!H', chksum(message)))[0]
    #message[2:4] = bytes(struct.pack('!H', chksum(message)))
    print("[sendICMPMessage] Sending message to", '{:12}'.format(socket.inet_ntoa(struct.pack('!I',dstIP))))

    if type == ICMP_ECHO_REQUEST_TYPE:
        with timeLock:
            icmp_send_times[dstIP + icmp_id + icmp_seqnum] = time.time()

    return sendIPDatagram(dstIP, message, ICMP_PROTO)

def initICMP():
    '''
        Nombre: initICMP
        Descripción: Esta función inicializa el nivel ICMP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

        Argumentos:
            -Ninguno
        Retorno: Ninguno

    '''
    #HACER
    registerIPProtocol(process_ICMP_message, ICMP_PROTO) #Mandar el proto en bytes?
    print("[initICMP] ICMP initialized succesfully")
    return

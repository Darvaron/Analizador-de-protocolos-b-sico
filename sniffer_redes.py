'''
Descripción: Analizador de protocolos
Autores:
    David Armando Rodríguez Varón - 20181020041
    Juan Sebastián Sanchez Tabares - 20181020008
    Johan Sneider Mendez Vega - 20172020070
    Juan Sebastián Mancera Gaitán - 20171020047
'''

import socket
import struct
import textwrap
import binascii

'''
Constantes para organizar la información
'''
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    #Ultimo argumento verifica que sea compatible entre todos los dispositivos
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    #ARP
    connarp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x003))

    while True: # Mientras reciba paquetes
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = capture_packages(raw_data)
        if eth_proto != 1544:
            print('\nPaquete :')
            print('Destino: {}, Origen: {}, Protocolo: {}'.format(dest_mac, src_mac,
                                                                 eth_proto))
        # 8 / IP
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ip_packet(data)
            print(TAB_1 + 'Paquete IP: ')
            print(TAB_2 + 'Versión {}, Longitud del encabezado: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocolo {}, Fuente: {}, Destino: {}'.format(proto, src, target))

            #ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'Paquete ICMP: ')
                print(TAB_2 + 'Tipo: {}, Código: {}, Checksum: {}, '.format(icmp_type, code, checksum))
                print(TAB_2 + 'Datos: ')
                print(format_multi_line(DATA_TAB_3, data))
            #TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + 'Segmento TCP: ')
                print(TAB_2 + 'Puerto de origen: {}, Puerto de destino: {}, '.format(src_port, dest_port))
                print(TAB_2 + 'Secuencia: {}, Acknowlodegment: {}, '.format(sequence, acknowledgement))
                print(TAB_2 + 'Banderas: ')
                print(TAB_3 + 'URG: {}, ACK, {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack,
                                                                                            flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Datos: ')
                print(format_multi_line(DATA_TAB_3, data))
            #UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'Segmento UDP:')
                print(TAB_2 + 'Puerto de origen: {}, Puerto de destino: {}, longitud: {}'.format(src_port, dest_port,
                                                                                                 length))
                print(TAB_2 + 'Datos: ')
                print(format_multi_line(DATA_TAB_3, data))
            #Otro
            else:
                print(TAB_1 + 'Datos: ')
                print(format_multi_line(DATA_TAB_1, data))      
        
        elif eth_proto != 1544:
            print(TAB_1 + 'Datos: ')
            print(format_multi_line(DATA_TAB_1, data))

        paquete_arp = connarp.recvfrom(2048)
        ethernet_header = paquete_arp[0][:14]
        ethernet_detalles = struct.unpack('!6s6s2s', ethernet_header)

        cabecera_arp = paquete_arp[0][14:42]
        arp_detalles = struct.unpack('2s2s1s1s2s6s4s6s4s', cabecera_arp)
        ethertype = ethernet_detalles[2]

        #Paquete ARP
        if ethertype == b'\x08\x06':
            print('\nPaquete ARP:')
            print(TAB_1 + 'Tipo de hardware: {}, Tipo de protocolo: {}'.format(str(binascii.hexlify(arp_detalles[0]), 'utf-8'),
                                                                               str(binascii.hexlify(arp_detalles[1]), 'utf-8')))
            print(TAB_1 + 'Tamaño del hardware: {}, Tamaño del protocolo: {}, opcode: {}'.format(str(binascii.hexlify(arp_detalles[2]), 'utf-8'),
                                                                                     str(binascii.hexlify(arp_detalles[3]), 'utf-8'),
                                                                                                 str(binascii.hexlify(arp_detalles[4]), 'utf-8')))
            print(TAB_1 + 'Dirección MAC origen: {}, Dirección IP origen: {}'.format(str(binascii.hexlify(arp_detalles[5]), 'utf-8'),
                                                                                     socket.inet_ntoa(arp_detalles[6])))
            print(TAB_1 + 'Dirección MAC destino: {}, Dirección IP destino: {}'.format(str(binascii.hexlify(arp_detalles[7]), 'utf-8'),
                                                                                     socket.inet_ntoa(arp_detalles[8])))
    
def capture_packages(data):
    '''
    Obtiene la información del paquete
    ---
    Sync -- Sincroniza el dispositivo y el router
    Receiver -- Quien lo recibe
    Sender -- Quien lo envia
    Type -- IP4, IP6, ARP, etc ...
    Payload -- (IP/ARP frame + padding), datos
    CRC -- manejo de errores, se asegura de que se reciba la información correctamente
    ---
    :param data: paquete
    :return: direcciones mac de destino, origen, tipo de protocolo y payload
    '''
    destination, source, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(destination), get_mac_addr(source), socket.htons(protocol), data[14:]

def get_mac_addr(bytes_addr):
    '''
    Pasa la dirección mac a formato legible
    :param bytes_addr: dirección mac en bytes
    :return: dirección mac en formato legible
    '''
    bytes_string = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_string).upper()

def ip_packet(data):
    '''
    Información que viene antes del payload
    ---
    Version
    IHL -- Longitud del encabezado
    TTL -- Time To Live
    Procol -- protocolo usado TCP, UDP etc 
    Source address -- ip de origen
    Destination address -- ip de destino
    ---
    :param data: paquete ip
    :return version, header_length, ttl, protocol, source ip, target ip, payload
    '''
    version_header_length = data[0]
    version = version_header_length >> 4 #Movimiento hacia la derecha
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    return version, header_length, ttl, proto, ipv(src), ipv(target), data[header_length:]

def ipv(addr):
    '''
    Pasa la dirección ip a formato legible
    :param addr: dirección ip en bytes
    :return dirección ip en formato XXX.XXX.X.X
    '''
    return '.'.join(map(str, addr))

def icmp_packet(data):
    '''
    Obtiene la información para el protocolo ICMP
    :param data: payload de tipo ICMP
    :return tipo de icmp, code, checksum, información del paquete
    '''
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])

    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    '''
    Obtiene la información para el protocolo TCP/IP
    :param data: datos de tipo TCP/IP
    :return puerto de origen, puerto de destino, sequence, acknowledgement, banderas, datos
    '''
    (source_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack(
        '! H H L L H', data[:14])

    offset = (offset_reserved_flags >> 12) * 4
    bandera_urg = (offset_reserved_flags & 32) >> 5
    bandera_ack = (offset_reserved_flags & 16) >> 4
    bandera_psh = (offset_reserved_flags & 8) >> 3
    bandera_rst = (offset_reserved_flags & 4) >> 2
    bandera_syn = (offset_reserved_flags & 2) >> 1
    bandera_fin = offset_reserved_flags & 1
    
    return source_port, dest_port, sequence, acknowledgement, bandera_urg, bandera_ack, bandera_psh, bandera_rst, bandera_syn, bandera_fin, data[offset:]

def udp_segment(data):
    '''
    Obtiene la información para el protocolo UDP
    :param data: payload de tipo UDP
    :return puerto de origen, puerto de destino, tamaño, información del paquete
    '''
    source_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, dest_port, size, data[8:]

#Organiza multi-line data
def format_multi_line(prefix, string, size= 80):
    '''
    Identa lineas para strings de gran tamaño
    :param prefix: prefijo
    :param string: data
    :param size: tamaño
    :return información identada
    '''
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == '__main__':
    main()

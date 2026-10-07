
import socket
import struct
import sys
import time
from flow_table import FlowTable

def parse_ethernet_header(data):
    "debemos primero extraer el protocolo ethernet y el payload"
    eth_header = struct.unpack("!6s6sH", data[0:14]) # ! indica que los datos estan en formato little endian, 6s6sH indica que los primeros dos campos son de 6 bytes y el ultimo de 2 bytes. [0:14] es porque la cabecera ethernet tiene 14 bytes de longitud
    eth_protocol = eth_header[2] #nos quedamos con el ultimo valor que es el protocolo
    return eth_protocol, data[14:]#el payload es todo lo que viene despues de la cabecera ethernet

def parse_ipv4_header(data):
    "Extrae direcciones IP, la longitud de cabecera y protocolo de transporte"
    version_ihl = data[0]
    ihl = (version_ihl & 0xF) * 4 #longitud de cabecera en bytes 
    ttl, proto, src, dst = struct.unpack('!8xBB2x4s4s', data[:20])# Aqui realizamos el unpacking de la cabecera ip
    src_ip = socket.inet_ntoa(src) # Convertimos la direccion ip a formato string
    dst_ip = socket.inet_ntoa(dst)# Convertimos la direccion ip a formato string
    return proto, src_ip, dst_ip, data[ihl:]#el payload es todo lo que viene despues de la cabecera ip

def parse_tcp_flags(flags_byte):
    "Decodifica flags TCP críticas para la detección de escaneos y SYN Floods"
    flags = {
        'FIN': bool(flags_byte & 0x01),
        'SYN': bool(flags_byte & 0x02),
        'RST': bool(flags_byte & 0x04),
        'PSH': bool(flags_byte & 0x08),
        'ACK': bool(flags_byte & 0x10),
        'URG': bool(flags_byte & 0x20)
    }
    return flags

def parse_tcp_header(data): 
    "Extrae puerots y banderas tcp"
    src_port, dest_port, seq, ack, ofset_reserved_flags = struct.unpack('!HHLLH', data[:14]) # HHLLH indica que los primeros dos campos son de 2 bytes y el ultimo de 2 bytes. [0:14] es porque la cabecera tcp tiene 14 bytes de longitud
    tcp_offset = ((ofset_reserved_flags >> 12) & 0x0F) * 4 #Calculamos el offset de la cabecera tcp
    flags_byte = ofset_reserved_flags & 0x3F
    flags = parse_tcp_flags(flags_byte)
    return src_port, dest_port, flags, data[tcp_offset:]#el payload es todo lo que viene despues de la cabecera tcp

def start_sniffer(interface = 'eth0'):
    try: 
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((interface, 0))
        print(f"Sniffer activo escuchando en interfaz : {interface}")
    except PermissionError:
        sys.exit("Error: Se requieren permisos de root para ejecutar el sniffer")
    except socket.error as e:
        sys.exit(f"Error de conexión con la interfaz {interface}: {e}")

    packet_count = 0
    start_time = time.time()
    flow_table = FlowTable(inactivity_timeout=3.0, max_packets_per_flow=500)
    last_timeout_check = time.time()
    

    try:
        while True:
            data, _ = raw_socket.recvfrom(65535)
            packet_count += 1

            eth_proto, payload = parse_ethernet_header(data)

            if eth_proto == 0x0800: #ipv4
                proto, src_ip, dst_ip, trans_data = parse_ipv4_header(payload)

                if proto == 6: #tcp
                    src_port, dst_port, flags, _ = parse_tcp_header(trans_data)
                    pkt_size = len(data)
                    flow_table.add_packet(src_ip, dst_ip, src_port, dst_port, proto, pkt_size, flags)
                    

                    #AQUI VA LOGICA DE ESCANEO DE PUERTOS DEL MODELO TODAVÍA NO SE INTEGRA
                    
                    flags_activas = [k for k, v in flags.items() if v]
                    if flags['SYN'] and not flags['ACK']:
                        print(f"[SYN DETECTADO] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags_activas}")
                    elif not flags_activas:
                        print(f"[ALERTA NULL SCAN] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags_activas}")
                    elif flags['FIN'] and flags['PSH'] and flags['URG']:
                        print(f"[ALERTA XMAS SCAN] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags_activas}")

            current_time = time.time()
            if current_time - last_timeout_check > 1.0: #revisa cada segundo
                close_flows = flow_table.check_timeouts()
                for flow_key, vector in close_flows:
                    #Aquí va lógica de ML 
                    print(f"[FLUJO CERRADO] {flow_key[0]}:{flow_key[2]} <-> {flow_key[1]}:{flow_key[3]}")
                    print(f"  └─> Vector: Pkts={vector[1]} | Var(IAT)={vector[6]:.4f} | H(Flags)={vector[8]:.2f}")
                    
                last_timeout_check = current_time

    except KeyboardInterrupt:
        print("\nSniffer detenido por el usuario")
        end_time = time.time()
        elapsed_time = end_time - start_time
        if elapsed_time > 0:
            print(f"Total de paquetes capturados: {packet_count}")
            print(f"Duracion del Sniffer: {elapsed_time:.2f} segundos")
            print(f"Tasa de captura: {packet_count / elapsed_time:.2f} paquetes/segundo")
        raw_socket.close()

if __name__ == "__main__":
    interface = "veth0" if len(sys.argv) < 2 else sys.argv[1]
    start_sniffer(interface)
                    
                
    
    
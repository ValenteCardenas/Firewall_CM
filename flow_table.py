import time
from extractor_vect import FlowFeatureExtractor

class FlowTable:
    def __init__(self, inactivity_timeout=5.0, max_packets_per_flow = 1000):
        self.active_flows = {}
        self.inactivity_timeout = inactivity_timeout
        self.max_packets = max_packets_per_flow

    #La siguiente funcion nos va a permitir generar la clave unica de cada flujo, esto para distinguir flujos iguales sin importar la direcion de la comunicacion, ademas de inicializar la tabla de flujos
    def _generate_key(self, src_ip, dst_ip, src_port, dst_port, proto):
        ips = sorted([src_ip, dst_ip])
        ports = sorted([src_port, dst_port])
        return (ips[0], ips[1], ports[0], ports[1], proto)
    
    #La siguiente funcion nos va a permitir añadir paquetes a la tabla de flujos, si el flujo no existe se crea, si existe se actualiza, ademas de verificar si el flujo debe ser cerrado por tiempo o por flags
    def add_packet(self, src_ip, dst_ip, src_port, dst_port, proto, pkt_size, flags_dict):
        flow_key = self._generate_key(src_ip, dst_ip, src_port, dst_port, proto)
        current_time = time.time()
        
        #Si el flujo no existe se crea, se guardan sus caracteristicas
        if flow_key not in self.active_flows:
            self.active_flows[flow_key]={
                'sizes': [],
                'timestamps': [],
                'dst_ports': [],
                'flags': [],
                'last_seen': current_time,
                'force_close': False
            }
        
        #Si el flujo existe se actualiza, se guardan sus caracteristicas
        flow = self.active_flows[flow_key]
        flow['sizes'].append(pkt_size)
        flow['timestamps'].append(current_time)
        flow['dst_ports'].append(dst_port)
        
        #Convertimos las flags a un byte para optimizar el espacio
        flag_byte = 0
        if flags_dict:
            flag_byte |= (flags_dict.get('FIN',False)<<0)
            flag_byte |= (flags_dict.get('SYN',False)<<1)
            flag_byte |= (flags_dict.get('RST',False)<<2)
            flag_byte |= (flags_dict.get('PSH',False)<<3)
            flag_byte |= (flags_dict.get('ACK',False)<<4)
            flag_byte |= (flags_dict.get('URG',False)<<5)
        flow['flags'].append(flag_byte)
        flow['last_seen'] = current_time
    
        #Si el flujo se cierra por flags o por tiempo se marca como cerrado
        if flags_dict and (flags_dict.get('FIN') or flags_dict.get('RST')):
            flow['force_close'] = True
        elif len(flow['sizes']) >= self.max_packets:
            flow['force_close'] = True
    
    #La siguiente funcion nos va a permitir verificar si algun flujo debe ser cerrado por tiempo o por flags
    def check_timeouts(self):
        current_time = time.time()
        expired_keys = []
        ready_vectors = []

        #Recorremos la tabla de flujos y verificamos si algun flujo debe ser cerrado por tiempo o por flags
        for key, flow in self.active_flows.items():
            inactive_time = current_time - flow['last_seen']
            if inactive_time > self.inactivity_timeout or flow['force_close']:
                vector = FlowFeatureExtractor.extraer_vector(
                    flow['sizes'],
                    flow['timestamps'],
                    flow['dst_ports'],
                    flow['flags']
                )
                ready_vectors.append((key, vector))

                expired_keys.append(key)
        
        #Eliminamos los flujos expirados de la tabla de flujos
        for key in expired_keys:
            del self.active_flows[key]
        
        return ready_vectors
            
        
        


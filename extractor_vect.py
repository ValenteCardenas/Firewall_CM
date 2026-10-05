import math
from collections import Counter

class FlowFeatureExtractor:

    @staticmethod
    def calcular_varianza(values):
        "Calculamos la varizanza de una lista de numeros"
        n = len(values)
        if n < 2:
            return 0.0
        media = sum(values) / n
        varianza = sum((x - media) ** 2 for x in values) / (n - 1)
        return float(varianza)

    @staticmethod
    def calcular_entropia(items):
        "Calculamos la entropia de shannon de una lista de un flujo en un vector matemático para el modelo"
        n = len(items)
        if n < 2:
            return 0.0
        counts = Counter(items)
        entropia = 0.0
        for c in counts.values():
            prob = c / n
            entropia -= prob * math.log2(prob)
        return float(entropia)
    
    @classmethod
    def extraer_vector(cls, packet_size, arrival_timestamps, dts_ports, tcp_flags_list):
        #Tiempos entre llegadas
        interarrival_list = []
        if len(arrival_timestamps) > 1:
            for i in range(1, len(arrival_timestamps)):
                diferencia = arrival_timestamps[i] - arrival_timestamps[i-1]
                interarrival_list.append(diferencia)

        var_packet_size = cls.calcular_varianza(packet_size)
        var_interarrival = cls.calcular_varianza(interarrival_list) if interarrival_list else 0.0

        entropia_puertos = cls.calcular_entropia(dts_ports)
        entropia_flags = cls.calcular_entropia(tcp_flags_list)

        duracion_flujo = arrival_timestamps[-1] - arrival_timestamps[0] if arrival_timestamps else 0.0 
        paquetes_conteo = len(packet_size)
        bytes_conteo = sum(packet_size)

        paquetes_por_segundo = paquetes_conteo / duracion_flujo if duracion_flujo > 0 else 0.0 
        bytes_por_segundo = bytes_conteo / duracion_flujo if duracion_flujo > 0 else 0.0 

        vector = [
            duracion_flujo,
            paquetes_conteo,
            bytes_conteo,
            paquetes_por_segundo,
            bytes_por_segundo,
            var_packet_size,
            var_interarrival,
            entropia_puertos,
            entropia_flags
        ]

        return vector


if __name__ == "__main__":
    extractor = FlowFeatureExtractor()

    # Escenario A: Ataque SYN Flood / Escaneo Vertical (Puertos rotando, banderas fijas, tamaños fijos)
    attack_sizes = [54] * 100
    attack_times = [i * 0.0001 for i in range(100)] # Intervalos fijos de 0.1 ms
    attack_ports = list(range(1000, 1100))          # 100 puertos distintos
    attack_flags = [0x02] * 100                     # Bandera SYN fija

    vec_attack = extractor.extraer_vector(attack_sizes, attack_times, attack_ports, attack_flags)
    
    # Escenario B: Tráfico Legítimo (Navegación Web)
    legit_sizes = [54, 60, 1500, 1500, 120, 850, 54, 1500]
    legit_times = [0.0, 0.02, 0.05, 0.051, 0.12, 0.35, 0.50, 0.52]
    legit_ports = [443] * len(legit_sizes)
    legit_flags = [0x02, 0x10, 0x18, 0x18, 0x10, 0x18, 0x11, 0x10] # SYN, ACK, PSH-ACK, FIN-ACK

    vec_legit = extractor.extraer_vector(legit_sizes, legit_times, legit_ports, legit_flags)

    print("COMPARATIVA MATEMÁTICA")
    print(f"Ataque    -> Var(Bytes): {vec_attack[5]:.2f} | H(Ports): {vec_attack[7]:.2f} | H(Flags): {vec_attack[8]:.2f}")
    print(f"Legítimo  -> Var(Bytes): {vec_legit[5]:.2f} | H(Ports): {vec_legit[7]:.2f} | H(Flags): {vec_legit[8]:.2f}")      

        
          
    
    
    
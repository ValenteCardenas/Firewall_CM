# Decisiones y Justificación del Proyecto

Este documento sirve como registro del diseño, arquitectura y decisiones técnicas tomadas hasta la fecha en el desarrollo del detector de anomalías de red.

## 1. Arquitectura del Sistema
El proyecto se ha dividido en tres componentes modulares, lo cual permite una clara separación de responsabilidades y facilita el mantenimiento y la escalabilidad del sistema:
- **Sniffer / Capturador (`sniffer_base.py`)**: Encargado de interactuar con la interfaz de red, capturar los paquetes crudos y extraer la información relevante a nivel de enlace, red y transporte.
- **Gestor de Flujos (`flow_table.py`)**: Agrupa de forma lógica los paquetes individuales en "flujos de comunicación", permitiendo analizar el contexto de una conexión a lo largo del tiempo.
- **Extractor de Características (`extractor_vect.py`)**: Procesa los datos crudos de cada flujo cerrado y calcula propiedades matemáticas y estadísticas para generar un vector, preparándolos para un posterior análisis mediante Inteligencia Artificial (Machine Learning).

## 2. Captura de Tráfico y Desempaquetado (Sniffer Base)
- **Decisión:** Uso de *raw sockets* (`socket.AF_PACKET`, `socket.SOCK_RAW`) y `struct.unpack` nativos en Python.
- **Justificación:** Aunque librerías de terceros como *Scapy* facilitan el análisis de paquetes, suelen ser muy pesadas e introducen una latencia alta en entornos de producción. Usar sockets crudos y desempaquetado a nivel de bytes garantiza un **alto rendimiento y velocidad** en la inspección en tiempo real.
- **Avance actual:** 
  - Desempaquetado eficiente de Ethernet, IPv4 y TCP.
  - Detección heurística rápida de anomalías básicas basada en banderas TCP (SYN Scan, NULL Scan y XMAS Scan) de manera inmediata.

## 3. Mantenimiento y Agrupación de Flujos (Flow Table)
- **Decisión:** Identificación de flujos ordenando las IPs y Puertos de menor a mayor antes de generar la clave del diccionario (`_generate_key`).
- **Justificación:** Esto hace que la captura de paquetes sea **bidireccional**. Es decir, tanto la petición (cliente $\rightarrow$ servidor) como la respuesta (servidor $\rightarrow$ cliente) se evalúan dentro del mismo flujo de contexto estadístico.
- **Decisión:** Uso de umbrales para cierre forzado de flujos (`inactivity_timeout` y `max_packets_per_flow`). También cierre inmediato si se detecta una bandera `FIN` o `RST`.
- **Justificación:** Evita problemas de **Memory Leak** (fugas de memoria) al mantener conexiones abiertas indefinidamente en memoria RAM. Delimita un tamaño máximo para procesar los flujos en fragmentos (chunks) más digeribles por el extractor de características.

## 4. Extracción Matemática de Características (Feature Extractor)
- **Decisión:** Implementar la **Varianza** para los tamaños de paquetes y el tiempo entre llegadas (IAT - Inter-Arrival Time).
- **Justificación:** Los ataques automatizados (ej. DoS, SYN Flood) suelen enviar ráfagas de paquetes idénticos a intervalos repetitivos, lo que genera una varianza en tamaños y tiempos cercana a 0. El tráfico humano/legítimo tiene mucha más variación.
- **Decisión:** Implementar la **Entropía de Shannon** para puertos y banderas TCP.
- **Justificación:** La entropía es clave para detectar ataques de fuerza bruta o escaneos de red. 
  - Un escaneo de puertos probará de forma secuencial una multitud de puertos, produciendo un índice de **alta entropía**. 
  - Una conexión web estándar interactúa repetitivamente con el mismo puerto (ej. 443), produciendo una entropía baja.
  - La combinación variada de flags (SYN $\rightarrow$ ACK $\rightarrow$ PSH $\rightarrow$ FIN) en tráfico legítimo difiere matemáticamente de la repetición constante de un ataque tipo SYN Flood.

## 5. Conclusión y Siguientes Pasos
El sistema base es robusto y puede recolectar de forma pasiva y procesar flujos en tiempo real sin saturar la memoria. Actualmente extrae un **vector final de 9 dimensiones** por cada flujo terminado.
El siguiente hito consistirá en pasar estos vectores a un modelo de Machine Learning y expandir la visibilidad hacia protocolos como UDP e ICMP.

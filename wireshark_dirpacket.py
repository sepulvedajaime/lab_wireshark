import pyshark

# Preparo archivo hashes.txt para almacer los hashes extraídos
f = open("hashes.txt", "w")

# Cargar el archivo de captura PCAP
file = 'tsys_cat_tcpdump_12_30.pcap'
pcap = pyshark.FileCapture(file, display_filter='f5ethtrailer.tls.keylog')

for packet in pcap:
    if hasattr(packet, 'f5ethtrailer'):
        # # Listar atributos disponibles
        # print("Atributos de F5ETHTRAILER:")
        # print(dir(packet.f5ethtrailer))

        # Acceder al Keylog entry
        keylog_entry = getattr(packet.f5ethtrailer, 'tls_keylog', None)
        
        if keylog_entry is not None:
            print(f'{keylog_entry}')
            f.write(f'{keylog_entry}\n')
        else:
            print('No se encontró Keylog Entry en este paquete.')
    else:
        print('Este paquete no tiene la capa F5ETHTRAILER.')

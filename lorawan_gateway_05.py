import socket
import json
import struct
import time
import os
import threading
import logging
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
import secrets

# Configuración del logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # Nivel mínimo que mostrará en pantalla
console_handler.setFormatter(formatter)
file_handler = logging.FileHandler(__file__ + ".log")
file_handler.setLevel(logging.DEBUG)  # Nivel mínimo que guardará en el archivo
file_handler.setFormatter(formatter)
#logger.addHandler(console_handler)
logger.addHandler(file_handler)

logger.info(f"Situación del log en {os.path.basename(__file__)}")
class BitUnpacker:
    """Clase para desempaquetar bits como en Rust"""
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.bit_pos = 0
    
    def u8(self):
        """Lee un byte (u8)"""
        if self.pos >= len(self.data):
            return 0
        val = self.data[self.pos]
        self.pos += 1
        return val
    
    def u16(self):
        """Lee un u16 en little endian"""
        if self.pos + 1 >= len(self.data):
            return 0
        val = struct.unpack('<H', self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        return val
    
    def f32(self):
        """Lee un f32 en little endian"""
        if self.pos + 3 >= len(self.data):
            return 0.0
        val = struct.unpack('<f', self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        return val
    
    def bits(self, count):
        """Lee un número específico de bits"""
        if self.pos >= len(self.data):
            return 0
        
        byte_val = self.data[self.pos]
        
        # Extraer los bits especificados
        if self.bit_pos == 0:
            # Primera llamada en este byte - bits altos
            val = (byte_val >> 4) & ((1 << count) - 1)
            self.bit_pos = 4
        else:
            # Segunda llamada en este byte - bits bajos
            val = byte_val & ((1 << count) - 1)
            self.bit_pos = 0
            self.pos += 1
        
        return val

class LoRaWANGateway:
    def __init__(self):
        # Configuración del gateway
        self.GATEWAY_ID = "AA555A0000000000"
        self.GATEWAY_EUI = bytes.fromhex(self.GATEWAY_ID)
        self.PORT = 1700
        '''
        <device name="Residuos 4281" device_number="1" device_class="dingtek" dev_eui="8CF9572000133C5C" join_eui="8CF9572000000000"  app_key="2B7E151628AED2A6ABF7158809CF4F3C" />
        <device name="Residuos 4259" device_number="2" device_class="dingtek" dev_eui="8CF957200016290F" join_eui="8CF9572000000000"  app_key="2B7E151628AED2A6ABF7158809CF4F3C" />
        <device name="Residuos Oficina" device_number="3" device_class="dingtek" dev_eui="8CF9572000059A3D" join_eui="8CF9572000000000"  app_key="2B7E151628AED2A6ABF7158809CF4F3C" />
        '''
        self.devices = [
            {"name": "Residuos 4281", "dev_eui": "8CF9572000133C5C", "device_number":1, "device_class":"dingtek"},
            {"name": "Residuos 4259", "dev_eui": "8CF957200016290F", "device_number":2, "device_class":"dingtek"},
            {"name": "Residuos Oficina", "dev_eui": "8CF9572000059A3D", "device_number":3, "device_class":"dingtek"},
        ]
        # Configuración del dispositivo
        self.DEV_EUI = "8CF9572000133C5C 8CF957200016290F 8CF9572000059A3D"
        self.JOIN_EUI = "8CF9572000000000"
        self.APP_EUI = self.JOIN_EUI
        self.APP_KEY = "2B7E151628AED2A6ABF7158809CF4F3C"
        
        # Claves derivadas (se generarán durante el join)
        self.app_s_key = None
        self.nwk_s_key = None
        self.dev_addr = None
        
        # Contadores
        self.join_nonce = 0
        self.dev_nonce = 0
        self.fcnt_up = 0
        self.fcnt_down = 0
        
        # Socket UDP
        self.sock = None
        self.client_addr = None
        
        # Estado del dispositivo
        self.device_joined = False
        
        # Payload para downlink
        self.DOWNLINK_PAYLOAD = bytes.fromhex("80029999010581")
        
    def start_gateway(self):
        """Inicia el gateway LoRaWAN"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('0.0.0.0', self.PORT))
            logger.info(f"Gateway iniciado en puerto {self.PORT}")
            logger.info(f"Gateway ID: {self.GATEWAY_ID}")
            
            # Hilo para enviar estadísticas periódicas
            stats_thread = threading.Thread(target=self.send_stats_loop, daemon=True)
            stats_thread.start()
            
            self.listen_loop()
            
        except Exception as e:
            logger.error(f"Error iniciando gateway: {e}")
        finally:
            if self.sock:
                self.sock.close()
    
    def listen_loop(self):
        """Loop principal para escuchar mensajes"""
        logger.info("Esperando mensajes...")
        
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.client_addr = addr
                logger.info(f"Mensaje recibido de {addr}, tamaño: {len(data)} bytes")
                
                # Procesar mensaje
                self.process_message(data)
                
            except Exception as e:
                logger.error(f"Error en loop principal: {e}")
    
    def process_message(self, data):
        """Procesa mensajes entrantes del packet forwarder"""
        if len(data) < 12:
            logger.warning("Mensaje demasiado corto")
            return
        
        # Header del protocolo Semtech
        version = data[0]
        token = struct.unpack('>H', data[1:3])[0]
        msg_type = data[3]
        
        logger.info(f"Versión: {version}, Token: {token:04X}, Tipo: {msg_type}")

        try:
            if msg_type == 0:  # PUSH_DATA
                self.handle_push_data(data, token)
            elif msg_type == 1:  # PUSH_ACK
                logger.info("PUSH_ACK recibido")
            elif msg_type == 2:  # PULL_DATA
                self.handle_pull_data(data, token)
            elif msg_type == 4:  # PULL_ACK
                logger.info("PULL_ACK recibido")
            else:
                logger.warning(f"Tipo de mensaje desconocido: {msg_type}")
        except Exception as e:
            logger.error(f"Error procesando mensaje tipo {msg_type}: {e}")
    
    def handle_push_data(self, data, token):
        """Maneja mensajes PUSH_DATA"""
        if len(data) < 12:
            return
        
        # Enviar ACK
        ack = struct.pack('BBH', 2, token >> 8, token & 0xFF) + b'\x01'
        self.sock.sendto(ack, self.client_addr)
        logger.info("PUSH_ACK enviado")
        
        # Extraer JSON payload
        try:
            json_str = data[12:].decode('utf-8')
            
            packet_data = json.loads(json_str)
            logger.info(f"\n\njson_str: {json_str}\npacket_data: {packet_data}\n")
            if 'rxpk' in packet_data:
                for rx_packet in packet_data['rxpk']:
                    self.process_rx_packet(rx_packet)
                    
        except Exception as e:
            logger.error(f"Error procesando PUSH_DATA: {e}")
    
    def handle_pull_data(self, data, token):
        """Maneja mensajes PULL_DATA"""
        # Enviar ACK
        ack = struct.pack('BBH', 2, token >> 8, token & 0xFF) + b'\x04'
        self.sock.sendto(ack, self.client_addr)
        logger.info("PULL_ACK enviado")
        logger.info(f"\n\ndata: {data.hex()}\ntoken: {token}\nack: {ack.hex()}\naddr: {self.client_addr}\n")

    
    def process_rx_packet(self, rx_packet):
        """Procesa un paquete LoRaWAN recibido"""
        if 'data' not in rx_packet:
            return
        
        try:
            # Decodificar base64
            import base64
            phy_payload = base64.b64decode(rx_packet['data'])
            logger.info(f"PHY Payload: {phy_payload.hex()}")
            
            # Analizar LoRaWAN MAC Header
            mhdr = phy_payload[0]
            msg_type = (mhdr >> 5) & 0x07
            
            logger.info(f"Tipo de mensaje LoRaWAN: {msg_type}")
            '''
            JoinRequest,
            JoinAccept,
            UnconfirmedDataUp,
            UnconfirmedDataDown,
            ConfirmedDataUp,
            ConfirmedDataDown,
            RejoinRequest,
            Proprietary,
            '''
            if msg_type == 0:  # Join Request
                logger.info("Join Request recibido")
                self.handle_join_request(phy_payload, rx_packet)
            elif msg_type == 1:  # Join Accept
                logger.info("Join Accept recibido")
            elif msg_type == 2:  # Unconfirmed Data Up
                logger.info("Unconfirmed Data Up recibido")            
                self.handle_unconfirmed_data_up(phy_payload, rx_packet)
            elif msg_type == 3:  # Unconfirmed Data Down
                logger.info("Unconfirmed Data Down recibido")                        
                self.handle_unconfirmed_data_down(phy_payload, rx_packet)                
            elif msg_type == 4:  # Confirmed Data Up
                logger.info("Confirmed Data Up recibido")                        
                self.handle_confirmed_data_up(phy_payload, rx_packet)
            elif msg_type == 5:  # Confirmed Data Down
                logger.info("Confirmed Data Down recibido")                        
                self.handle_confirmed_data_down(phy_payload, rx_packet)                
            elif msg_type == 6:  # Join Accept
                logger.info("RejoinRequest recibido")                
            elif msg_type == 7:  # Join Accept
                logger.info("Propietary recibido")                

            else:
                logger.info(f"Tipo de mensaje no manejado: {msg_type}")
                
        except Exception as e:
            logger.error(f"Error procesando paquete RX: {e}")
    
    def handle_join_request(self, phy_payload, rx_packet):
        """Maneja Join Request y envía Join Accept"""
        logger.info("=== JOIN REQUEST RECIBIDO ===")
        
        try:
            # Extraer campos del Join Request
            app_eui = phy_payload[1:9][::-1]  # Reverse byte order
            dev_eui = phy_payload[9:17][::-1]  # Reverse byte order
            dev_nonce = struct.unpack('<H', phy_payload[17:19])[0]
            
            logger.info(f"AppEUI: {app_eui.hex()}")
            logger.info(f"DevEUI: {dev_eui.hex()}")
            logger.info(f"DevNonce: {dev_nonce:04X}")
            
            # Verificar EUIs
            expected_app_eui = bytes.fromhex(self.APP_EUI)
            expected_dev_eui = bytes.fromhex(self.DEV_EUI)
            
            if app_eui == expected_app_eui and  any(bytes.fromhex(device["dev_eui"]) == dev_eui for device in self.devices):# dev_eui in expected_dev_eui:# dev_eui == expected_dev_eui:
                logger.info("✓ EUIs válidos, enviando Join Accept")
                self.send_join_accept(rx_packet, dev_nonce)
            else:
                logger.warning("✗ EUIs no coinciden")
                
        except Exception as e:
            logger.error(f"Error en Join Request: {e}")
    
    def send_join_accept(self, rx_packet, dev_nonce):
        """Envía Join Accept"""
        try:
            # Generar parámetros
            self.join_nonce = secrets.randbits(24)  # 3 bytes
            self.dev_addr = secrets.randbits(32)    # 4 bytes
            
            logger.info(f"JoinNonce: {self.join_nonce:06X}")
            logger.info(f"DevAddr: {self.dev_addr:08X}")
            
            # Derivar claves de sesión
            self.derive_session_keys(dev_nonce)
            
            # Construir Join Accept
            mhdr = 0x20  # Join Accept
            join_nonce_bytes = struct.pack('<I', self.join_nonce)[:3]
            net_id = b'\x00\x00\x00'  # 3 bytes
            dev_addr_bytes = struct.pack('<I', self.dev_addr)
            dl_settings = 0x00
            rx_delay = 0x01
            
            # Payload sin cifrar
            join_accept_payload = (join_nonce_bytes + net_id + dev_addr_bytes + 
                                 bytes([dl_settings, rx_delay]))
            
            # Cifrar con AppKey
            app_key = bytes.fromhex(self.APP_KEY)
            cipher = AES.new(app_key, AES.MODE_ECB)
            encrypted_payload = cipher.encrypt(join_accept_payload.ljust(16, b'\x00'))[:len(join_accept_payload)]
            
            # Construir mensaje completo
            full_message = bytes([mhdr]) + encrypted_payload
            
            # Calcular MIC
            mic = self.calculate_join_accept_mic(full_message, app_key)
            full_message += mic
            
            # Enviar downlink
            self.send_downlink(full_message, rx_packet)
            
            # Marcar dispositivo como joined
            self.device_joined = True
            self.fcnt_up = 0
            self.fcnt_down = 0
            
            logger.info("✓ Join Accept enviado exitosamente")
            
        except Exception as e:
            logger.error(f"Error enviando Join Accept: {e}")
    
    def derive_session_keys(self, dev_nonce):
        """Deriva las claves de sesión AppSKey y NwkSKey"""
        try:
            app_key = bytes.fromhex(self.APP_KEY)
            
            # Preparar datos para derivación
            join_nonce_bytes = struct.pack('<I', self.join_nonce)[:3]
            join_eui = bytes.fromhex(self.JOIN_EUI)
            dev_nonce_bytes = struct.pack('<H', dev_nonce)
            
            # NwkSKey = aes128_encrypt(AppKey, 0x01 | JoinNonce | JoinEUI | DevNonce | pad16)
            nwk_data = b'\x01' + join_nonce_bytes + join_eui + dev_nonce_bytes
            nwk_data = nwk_data.ljust(16, b'\x00')
            
            # AppSKey = aes128_encrypt(AppKey, 0x02 | JoinNonce | JoinEUI | DevNonce | pad16)
            app_data = b'\x02' + join_nonce_bytes + join_eui + dev_nonce_bytes
            app_data = app_data.ljust(16, b'\x00')
            
            cipher = AES.new(app_key, AES.MODE_ECB)
            self.nwk_s_key = cipher.encrypt(nwk_data)
            self.app_s_key = cipher.encrypt(app_data)
            
            logger.info(f"NwkSKey: {self.nwk_s_key.hex()}")
            logger.info(f"AppSKey: {self.app_s_key.hex()}")
            
        except Exception as e:
            logger.error(f"Error derivando claves: {e}")
    
    def calculate_join_accept_mic(self, message, key):
        """Calcula MIC para Join Accept"""
        logger.info(f"key: {type(key)} Message: {type(message)}")
        try:
            cobj = CMAC.new(bytes(key), ciphermod=AES)
        except Exception as e:
            logger.error(f"Join Accept 1 Error calculando MIC: {e}")
            return b'\x00\x00\x00\x00'
        try:
            cobj.update(message)
        except Exception as e:
            logger.error(f"Join Accept 2 Error calculando MIC: {e}")
            return b'\x00\x00\x00\x00'
        try:
            return cobj.digest()[:4]
        except Exception as e:
            logger.error(f"Join Accept 3 Error calculando MIC: {e}")
            return b'\x00\x00\x00\x00'

    def handle_unconfirmed_data_up(self, phy_payload, rx_packet):
        """Maneja Unconfirmed Data Up y analiza el payload"""
        if not self.device_joined:
            logger.warning("Dispositivo no joined, ignorando uplink")
            return
        
        logger.info("=== UNCONFIRMED DATA UP RECIBIDO ===")
        
        try:
            # Extraer campos
            mhdr = phy_payload[0]
            dev_addr = struct.unpack('<I', phy_payload[1:5])[0]
            fctrl = phy_payload[5]
            fcnt = struct.unpack('<H', phy_payload[6:8])[0]
            
            logger.info(f"DevAddr: {dev_addr:08X}")
            logger.info(f"FCnt: {fcnt}")
            
            if dev_addr == self.dev_addr:
                # Extraer payload
                fport_start = 8
                if fctrl & 0x0F > 0:  # FOpts presente
                    fport_start += (fctrl & 0x0F)
                
                if fport_start < len(phy_payload) - 4:  # -4 para MIC
                    fport = phy_payload[fport_start]
                    encrypted_payload = phy_payload[fport_start + 1:-4]
                    
                    logger.info(f"FPort: {fport}")
                    logger.info(f"Payload cifrado: {encrypted_payload.hex()}")
                    
                    # Descifrar payload
                    decrypted_payload = self.decrypt_payload(encrypted_payload, fcnt, 0, fport)
                    logger.info(f"Payload descifrado: {decrypted_payload.hex()}")
                    
                    # Analizar payload personalizado
                    self.analyze_custom_payload(decrypted_payload)
                    
                    # Enviar downlink automático
                    threading.Thread(target=self.send_automatic_downlink, 
                                   args=(rx_packet,), daemon=True).start()
                
        except Exception as e:
            logger.error(f"Error procesando Unconfirmed Data Up: {e}")
    def handle_unconfirmed_data_down(self, phy_payload, rx_packet):
        """Maneja Unconfirmed Data Down y analiza el payload"""
        if not self.device_joined:
            logger.warning("Dispositivo no joined, ignorando uplink")
            return
        
        logger.info("=== UNCONFIRMED DATA DOWN RECIBIDO ===")
        
        try:
            # Extraer campos
            mhdr = phy_payload[0]
            dev_addr = struct.unpack('<I', phy_payload[1:5])[0]
            fctrl = phy_payload[5]
            fcnt = struct.unpack('<H', phy_payload[6:8])[0]
            
            logger.info(f"DevAddr: {dev_addr:08X}")
            logger.info(f"FCnt: {fcnt}")
            
            if dev_addr == self.dev_addr:
                # Extraer payload
                fport_start = 8
                if fctrl & 0x0F > 0:  # FOpts presente
                    fport_start += (fctrl & 0x0F)
                
                if fport_start < len(phy_payload) - 4:  # -4 para MIC
                    fport = phy_payload[fport_start]
                    encrypted_payload = phy_payload[fport_start + 1:-4]
                    
                    logger.info(f"FPort: {fport}")
                    logger.info(f"Payload cifrado: {encrypted_payload.hex()}")
                    
                    # Descifrar payload
                    decrypted_payload = self.decrypt_payload(encrypted_payload, fcnt, 0, fport)
                    logger.info(f"Payload descifrado: {decrypted_payload.hex()}")
                    
                    # Analizar payload personalizado
                    self.analyze_custom_payload(decrypted_payload)
                    
                    # Enviar downlink automático
                    threading.Thread(target=self.send_automatic_downlink, 
                                   args=(rx_packet,), daemon=True).start()
                
        except Exception as e:
            logger.error(f"Error procesando Un confirmed Data Up: {e}")   

    def handle_confirmed_data_up(self, phy_payload, rx_packet):
        """Maneja Confirmed Data Up"""
        logger.info("=== CONFIRMED DATA UP RECIBIDO ===")
        # Similar al unconfirmed pero requiere ACK
        self.handle_unconfirmed_data_up(phy_payload, rx_packet)
    
    def handle_confirmed_data_down(self, phy_payload, rx_packet):
        """Maneja Confirmed Data Down"""
        logger.info("=== CONFIRMED DATA DOWN RECIBIDO ===")
        # Similar al unconfirmed pero requiere ACK
        self.handle_unconfirmed_data_down(phy_payload, rx_packet)

    def analyze_custom_payload(self, data):
        """Analiza el payload personalizado según especificaciones"""
        logger.info("=== ANÁLISIS DE PAYLOAD PERSONALIZADO ===")
        
        if len(data) < 7:  # Mínimo: 5 bytes cabecera + 2 bytes final
            logger.warning("Payload demasiado corto")
            return
        
        try:
            # Verificar cabecera
            if data[0] != 0x80:
                logger.warning(f"Primer byte incorrecto: {data[0]:02X} (esperado: 80)")
                return
            
            if data[1] != 0x00:
                logger.warning(f"Segundo byte incorrecto: {data[1]:02X} (esperado: 00)")
                return
            
            device_type = data[2]
            record_data_type = data[3]
            packet_size = data[4]
            
            logger.info(f"✓ Cabecera válida:")
            logger.info(f"  Device Type: {device_type}")
            logger.info(f"  Record Data Type: {record_data_type}")
            logger.info(f"  Packet Size: {packet_size}")
            
            # Verificar tamaño
            if packet_size != len(data):
                logger.warning(f"Tamaño incorrecto: {len(data)} vs esperado {packet_size}")
                return
            
            # Extraer payload (entre cabecera y final)
            payload = data[5:-2]  # Sin cabecera (5 bytes) ni final (2 bytes)
            frame_count = struct.unpack('<H', data[-2:])[0]  # 2 bytes finales
            
            logger.info(f"Payload length: {len(payload)} bytes")
            logger.info(f"Frame count: {frame_count}")
            
            # Analizar según record_data_type
            if record_data_type in [1, 2]:
                self.parse_sensor_payload(payload)
            else:
                logger.info(f"Record data type {record_data_type} no implementado")
                
        except Exception as e:
            logger.error(f"Error analizando payload: {e}")
    
    def parse_sensor_payload(self, payload):
        """Parsea payload de sensores según estructura Rust"""
        logger.info("=== PARSEANDO DATOS DE SENSORES ===")
        
        try:
            payload_len = len(payload)
            battery_check = payload_len == 12
            
            unpacker = BitUnpacker(payload)
            
            # Leer campos
            height = unpacker.u16()
            gps_present = unpacker.u8()
            
            longitude = 0.0
            latitude = 0.0
            battery_volt = 0
            
            if gps_present == 1:
                battery_check = payload_len == 20
                longitude = unpacker.f32()
                latitude = unpacker.f32()
            
            temperature = unpacker.u8()
            reserved = unpacker.u8()
            angle = unpacker.u8()
            
            full_status = unpacker.bits(4)
            fire_status = unpacker.bits(4)
            fall_status = unpacker.bits(4)
            power_status = unpacker.bits(4)
            
            if battery_check:
                battery_volt = unpacker.u16()
            
            frame_count = unpacker.u16()
            
            # Mostrar resultados
            logger.info(f"   height: {height} mm")
            logger.info(f"   temperature: {temperature} ºC")
            logger.info(f"   angle: {angle} º")
            logger.info(f"   full_status: {full_status}")
            logger.info(f"   fire_status: {fire_status}")
            logger.info(f"   fall_status: {fall_status}")
            logger.info(f"   power_status: {power_status}")
            
            if gps_present == 1:
                logger.info(f"   longitude: {longitude:.6f}")
                logger.info(f"   latitude: {latitude:.6f}")
            
            if battery_check:
                logger.info(f"   battery volt: {battery_volt / 100.0:.2f}v")
            
            logger.info(f"   frame count: {frame_count}")
            
        except Exception as e:
            logger.error(f"Error parseando sensores: {e}")
    
    def send_automatic_downlink(self, rx_packet):
        """Envía downlink automático después de recibir UnconfirmedDataUp"""
        try:
            # Esperar un poco antes de enviar (simular procesamiento)
            time.sleep(0.5)
            
            logger.info("=== ENVIANDO DOWNLINK AUTOMÁTICO ===")
            
            # Construir mensaje de downlink
            mhdr = 0x60  # Unconfirmed Data Down
            dev_addr_bytes = struct.pack('<I', self.dev_addr)
            fctrl = 0x00
            fcnt_bytes = struct.pack('<H', self.fcnt_down)
            fport = 1
            
            # Cifrar payload
            encrypted_payload = self.encrypt_payload(self.DOWNLINK_PAYLOAD, self.fcnt_down, 1, fport)
            
            # Construir mensaje completo
            mac_payload = (dev_addr_bytes + bytes([fctrl]) + fcnt_bytes + 
                          bytes([fport]) + encrypted_payload)
            full_message = bytes([mhdr]) + mac_payload
            
            # Calcular MIC
            mic = self.calculate_mic(full_message, self.fcnt_down, 1)  # 1 = downlink
            full_message += mic
            
            # Enviar
            self.send_downlink(full_message, rx_packet)
            
            self.fcnt_down += 1
            logger.info(f"✓ Downlink enviado con payload: {self.DOWNLINK_PAYLOAD.hex()}")
            
        except Exception as e:
            logger.error(f"Error enviando downlink automático: {e}")
    
    def decrypt_payload(self, payload, fcnt, direction, fport):
        """Descifrar payload LoRaWAN"""
        if fport == 0:
            key = self.nwk_s_key
        else:
            key = self.app_s_key
        
        return self.crypt_payload(payload, key, fcnt, direction)
    
    def encrypt_payload(self, payload, fcnt, direction, fport):
        """Cifrar payload LoRaWAN"""
        if fport == 0:
            key = self.nwk_s_key
        else:
            key = self.app_s_key
        
        return self.crypt_payload(payload, key, fcnt, direction)
    
    def crypt_payload(self, payload, key, fcnt, direction):
        """Cifra/descifra payload usando AES-128 CTR"""
        try:
            if not payload:
                return b''
            
            result = bytearray()
            
            for i in range(0, len(payload), 16):
                # Construir bloque A
                a_block = bytearray(16)
                a_block[0] = 0x01
                a_block[5] = direction
                a_block[6:10] = struct.pack('<I', self.dev_addr)
                a_block[10:14] = struct.pack('<I', fcnt)
                a_block[15] = (i // 16) + 1
                
                # Cifrar bloque A
                cipher = AES.new(key, AES.MODE_ECB)
                s_block = cipher.encrypt(bytes(a_block))
                
                # XOR con payload
                chunk = payload[i:i+16]
                for j in range(len(chunk)):
                    result.append(chunk[j] ^ s_block[j])
            
            return bytes(result)
            
        except Exception as e:
            logger.error(f"Error cifrando/descifrando: {e}")
            return payload
    
    def calculate_mic(self, message, fcnt, direction):
        """Calcula MIC para mensajes de datos"""
        try:
            logger.info(f"fcnt: {type(fcnt)} Message: {type(message)} Direction: {type(direction)}")

            # Construir B0
            b0 = bytearray(16)
            b0[0] = 0x49
            b0[5] = direction
            b0[6:10] = struct.pack('<I', self.dev_addr)
            b0[10:14] = struct.pack('<I', fcnt)
            message_bytes = bytes(message)
            b0[15] = len(message_bytes)
            
            # Calcular CMAC
            cobj = CMAC.new(self.nwk_s_key, ciphermod=AES)
            cobj.update(bytes(b0))
            cobj.update(message_bytes)
            
            return cobj.digest()[:4]
            
        except Exception as e:
            logger.error(f"Calculate MIC Error calculando MIC: {e}")
            return b'\x00\x00\x00\x00'
    
    def send_downlink(self, phy_payload, rx_packet):
        """Envía mensaje de downlink"""
        try:
            import base64
            
            # Preparar mensaje PULL_RESP
            token = secrets.randbits(16)
            
            # Construir JSON para downlink
            tx_packet = {
                "txpk": {
                    "imme": False,
                    "tmst": rx_packet.get("tmst", 0) + 1000000,  # 1 segundo después
                    "freq": rx_packet.get("freq", 868.1),
                    "rfch": 0,
                    "powe": 14,
                    "modu": "LORA",
                    "datr": rx_packet.get("datr", "SF7BW125"),
                    "codr": "4/5",
                    "ipol": True,
                    "size": len(phy_payload),
                    "data": base64.b64encode(phy_payload).decode()
                }
            }
            
            # Construir mensaje PULL_RESP
            json_data = json.dumps(tx_packet).encode()
            message = struct.pack('BBH', 2, token >> 8, token & 0xFF) + b'\x03' + json_data
            
            # Enviar
            if self.client_addr:
                self.sock.sendto(message, self.client_addr)
                logger.info(f"Downlink enviado: {len(phy_payload)} bytes")
            
        except Exception as e:
            logger.error(f"Error enviando downlink: {e}")
    
    def send_stats_loop(self):
        """Envía estadísticas periódicamente"""
        while True:
            try:
                time.sleep(30)  # Cada 30 segundos
                
                if self.client_addr:
                    stats = {
                        "stat": {
                            "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S GMT"),
                            "rxnb": 0,
                            "rxok": 0,
                            "rxfw": 0,
                            "ackr": 100.0,
                            "dwnb": 0,
                            "txnb": 0
                        }
                    }
                    
                    token = secrets.randbits(16)
                    json_data = json.dumps(stats).encode()
                    message = (struct.pack('BBH', 2, token >> 8, token & 0xFF) + 
                              self.GATEWAY_EUI + json_data)
                    
                    self.sock.sendto(message, self.client_addr)
                    logger.debug("Estadísticas enviadas")
                    
            except Exception as e:
                logger.error(f"Error enviando estadísticas: {e}")

def main():
    """Función principal"""
    print("=== Gateway LoRaWAN OTAA ===")
    print("Iniciando servidor...")
    
    gateway = LoRaWANGateway()
    
    try:
        gateway.start_gateway()
    except KeyboardInterrupt:
        print("\nDeteniendo gateway...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

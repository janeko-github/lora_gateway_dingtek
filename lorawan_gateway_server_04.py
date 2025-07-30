#!/usr/bin/env python3
"""
LoRaWAN Gateway Server con soporte OTAA
Protocolo Semtech UDP para comunicación con gateway
"""

import socket
import json
import struct
import time
import threading
import logging
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
fh = logging.FileHandler(__file__ + ".log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
fh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.info(f"Situación del log en {os.path.basename(__file__)}")


class LoRaWANServer:
    def __init__(self):
        # Configuración del servidor
        self.SERVER_HOST = "0.0.0.0"
        self.SERVER_PORT = 1700
        
        # Identificadores del gateway
        self.GATEWAY_ID = "AA555A0000000000"
        
        # Identificadores del dispositivo (parametrizables)
        self.DEV_EUI = "8CF9572000133C5C"
        self.JOIN_EUI = "8CF9572000000000"
        self.APP_EUI = self.JOIN_EUI
        self.APP_KEY = "2B7E151628AED2A6ABF7158809CF4F3C"
        
        # Payload para downlink
        self.DOWNLINK_PAYLOAD = "80029999010181"
        
        # Estado de sesión del dispositivo
        self.device_sessions = {}
        
        # Socket UDP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.SERVER_HOST, self.SERVER_PORT))
        
        # Dirección del gateway
        self.gateway_addr = None
        
        logger.info(f"{datetime.now()}  Servidor LoRaWAN iniciado en {self.SERVER_HOST}:{self.SERVER_PORT}")
        logger.info(f"{datetime.now()}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        logger.info(f"{datetime.now()}  📡 Gateway ID esperado: {self.GATEWAY_ID}")
        logger.info(f"{datetime.now()}  🔧 Configuración del dispositivo:")
        logger.info(f"{datetime.now()}     Device EUI:  {self.DEV_EUI}")
        logger.info(f"{datetime.now()}     Join EUI:    {self.JOIN_EUI}")
        logger.info(f"{datetime.now()}     App Key:     {self.APP_KEY}")
        logger.info(f"{datetime.now()}  📤 Payload downlink: {self.DOWNLINK_PAYLOAD}")
        logger.info(f"{datetime.now()}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        logger.info(f"{datetime.now()}  ⏳ Esperando conexión del gateway...")
        
    def aes128_encrypt(self, key, data):
        """Encriptar usando AES-128-ECB"""
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()
    
    def generate_keys(self, app_nonce, net_id, dev_nonce):
        """Generar claves de sesión para OTAA"""
        app_key = binascii.unhexlify(self.APP_KEY)
        
        # NwkSKey
        nwk_s_key_data = bytes([0x01]) + app_nonce + net_id + dev_nonce + bytes(7)
        nwk_s_key = self.aes128_encrypt(app_key, nwk_s_key_data)
        
        # AppSKey
        app_s_key_data = bytes([0x02]) + app_nonce + net_id + dev_nonce + bytes(7)
        app_s_key = self.aes128_encrypt(app_key, app_s_key_data)
        
        return nwk_s_key, app_s_key
    
    def create_join_accept(self, dev_nonce):
        """Crear mensaje Join Accept"""
        # Generar valores aleatorios
        app_nonce = os.urandom(3)  # 3 bytes
        net_id = bytes([0x00, 0x00, 0x00])  # 3 bytes
        dev_addr = os.urandom(4)  # 4 bytes
        
        # Generar claves de sesión
        nwk_s_key, app_s_key = self.generate_keys(app_nonce, net_id, dev_nonce)
        
        # Construir Join Accept payload (sin MHDR)
        join_accept_payload = bytearray()
        join_accept_payload.extend(app_nonce)  # AppNonce (3 bytes)
        join_accept_payload.extend(net_id)     # NetID (3 bytes)
        join_accept_payload.extend(dev_addr)   # DevAddr (4 bytes)
        join_accept_payload.append(0x00)       # DLSettings (1 byte)
        join_accept_payload.append(0x05)       # RxDelay (1 byte)
        
        # Calcular MIC (simplificado - en producción usar CMAC)
        mic = bytes([0x00, 0x00, 0x00, 0x00])
        join_accept_payload.extend(mic)
        
        # Encriptar Join Accept payload
        app_key = binascii.unhexlify(self.APP_KEY)
        encrypted_payload = self.aes128_encrypt(app_key, bytes(join_accept_payload))
        
        # Crear mensaje completo con MHDR
        mhdr = 0x20  # Join Accept
        complete_message = bytearray()
        complete_message.append(mhdr)
        complete_message.extend(encrypted_payload[:16])  # Join Accept es de 17 bytes total
        
        # Almacenar sesión del dispositivo
        dev_addr_hex = binascii.hexlify(dev_addr).decode().upper()
        self.device_sessions[dev_addr_hex] = {
            'dev_eui': self.DEV_EUI,
            'dev_addr': dev_addr_hex,
            'nwk_s_key': nwk_s_key,
            'app_s_key': app_s_key,
            'fcnt_up': 0,
            'fcnt_down': 0,
            'app_nonce': app_nonce,
            'net_id': net_id
        }
        
        logger.info(f"{datetime.now()}  create_join_accept Sesión creada para dispositivo: {dev_addr_hex}")
        logger.info(f"{datetime.now()}  AppNonce: {binascii.hexlify(app_nonce).decode().upper()}")
        logger.info(f"{datetime.now()}  DevAddr: {dev_addr_hex}")
        logger.info(f"{datetime.now()}  Sesiones disponibles: {list(self.device_sessions.keys())}")
        return bytes(complete_message)
    
    def create_downlink_message(self, dev_addr, payload_hex):
        """Crear mensaje de downlink"""
        if dev_addr not in self.device_sessions:
            logger.info(f"{datetime.now()} create_downlink_message  No hay sesión para el dispositivo: {dev_addr}")
            logger.info(f"{datetime.now()}     Sesiones disponibles: {list(self.device_sessions.keys())}")
            return None
            
        session = self.device_sessions[dev_addr]
        
        # Incrementar contador de downlink
        session['fcnt_down'] += 1
        
        # Construir mensaje downlink
        mhdr = 0x60  # Unconfirmed Data Down
        dev_addr_bytes = binascii.unhexlify(dev_addr)
        fctrl = 0x00
        fcnt = session['fcnt_down'].to_bytes(2, 'little')
        
        # Payload
        payload_bytes = binascii.unhexlify(payload_hex)
        
        # Construir frame
        frame = bytearray()
        frame.append(mhdr)
        frame.extend(dev_addr_bytes)
        frame.append(fctrl)
        frame.extend(fcnt)
        frame.extend(payload_bytes)
        
        # MIC simplificado
        mic = bytes([0x00, 0x00, 0x00, 0x00])
        frame.extend(mic)
        
        return bytes(frame)
    
    def handle_pull_data(self, data, addr):
        """Manejar mensaje PULL_DATA del gateway"""
        if len(data) < 12:
            return
            
        protocol_version = data[0]
        random_token = data[1:3]
        identifier = data[3]
        gateway_id = binascii.hexlify(data[4:12]).decode().upper()
        
        if gateway_id != self.GATEWAY_ID:
            if self.gateway_addr != addr:
                logger.info(f"{datetime.now()}  🔗 Gateway conectado: {gateway_id}")
                logger.info(f"{datetime.now()}     IP: {addr[0]}:{addr[1]}")
            self.gateway_addr = addr
            
            # Responder con PULL_ACK
            response = bytearray()
            response.append(protocol_version)
            response.extend(random_token)
            response.append(0x04)  # PULL_ACK
            
            self.sock.sendto(response, addr)
        else:
            logger.info(f"{datetime.now()}  ⚠️  Gateway no autorizado: {gateway_id} (esperado: {self.GATEWAY_ID})")
    
    def handle_push_data(self, data, addr):
        """Manejar mensaje PUSH_DATA del gateway"""
        if len(data) < 12:
            return
            
        protocol_version = data[0]
        random_token = data[1:3]
        identifier = data[3]
        gateway_id = binascii.hexlify(data[4:12]).decode().upper()
        
        if len(data) > 12:
            try:
                json_payload = data[12:].decode('utf-8')
                packet_data = json.loads(json_payload)
                
                logger.info(f"{datetime.now()}  PUSH_DATA recibido del gateway: {gateway_id}")
                logger.info(f"{datetime.now()}  Datos: {json.dumps(packet_data, indent=2)}")
                
                # Procesar paquetes recibidos
                if 'rxpk' in packet_data:
                    for rxpk in packet_data['rxpk']:
                        self.process_uplink(rxpk, addr)
                        
            except json.JSONDecodeError:
                logger.info(f"{datetime.now()}  Error decodificando JSON en PUSH_DATA")
        
        # Responder con PUSH_ACK
        response = bytearray()
        response.append(protocol_version)
        response.extend(random_token)
        response.append(0x01)  # PUSH_ACK
        
        self.sock.sendto(response, addr)
        logger.info(f"{datetime.now()}  PUSH_ACK enviado")
    
    def process_uplink(self, rxpk, addr):
        """Procesar mensaje uplink"""
        if 'data' not in rxpk:
            return
            
        try:
            # Decodificar payload base64
            payload = binascii.a2b_base64(rxpk['data'])
            payload_hex = binascii.hexlify(payload).decode().upper()
            
            logger.info(f"{datetime.now()}  \n--- Nuevo mensaje uplink ---")
            logger.info(f"{datetime.now()}  Timestamp: {datetime.now().strftime('%H:%M:%S')}")
            logger.info(f"{datetime.now()}  Frecuencia: {rxpk.get('freq', 'N/A')} MHz")
            logger.info(f"{datetime.now()}  RSSI: {rxpk.get('rssi', 'N/A')} dBm")
            logger.info(f"{datetime.now()}  SNR: {rxpk.get('lsnr', 'N/A')} dB")
            logger.info(f"{datetime.now()}  Data Rate: {rxpk.get('datr', 'N/A')}")
            logger.info(f"{datetime.now()}  Payload: {payload_hex}")
            
            if len(payload) < 1:
                logger.info(f"{datetime.now()}  Payload vacío")
                return
                
            mhdr = payload[0]
            msg_type = (mhdr >> 5) & 0x07
            
            logger.info(f"{datetime.now()}  MHDR: 0x{mhdr:02X}")
            logger.info(f"{datetime.now()}  Tipo de mensaje: {msg_type}")
            
            if msg_type == 0:  # Join Request
                logger.info(f"{datetime.now()}  📥 Procesando Join Request")
                self.handle_join_request(payload, rxpk)
                
            elif msg_type == 2:  # Unconfirmed Data Up
                logger.info(f"{datetime.now()}  📥 Procesando Unconfirmed Data Up")
                self.handle_unconfirmed_data_up(payload, rxpk)
                
            elif msg_type == 4:  # Confirmed Data Up
                logger.info(f"{datetime.now()}  📥 Procesando Confirmed Data Up")
                self.handle_confirmed_data_up(payload, rxpk)
            else:
                logger.info(f"{datetime.now()}  Tipo de mensaje no soportado: {msg_type}")
                
        except Exception as e:
            logger.info(f"{datetime.now()}  ❌ Error procesando uplink: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_join_request(self, payload, rxpk):
        """Manejar Join Request"""
        if len(payload) < 23:
            logger.info(f"{datetime.now()}  Join Request muy corto")
            return
            
        # Extraer campos del Join Request
        join_eui = binascii.hexlify(payload[1:9][::-1]).decode().upper()
        dev_eui = binascii.hexlify(payload[9:17][::-1]).decode().upper()
        dev_nonce = payload[17:19]
        mic = payload[19:23]
        
        logger.info(f"{datetime.now()}  Join Request recibido:")
        logger.info(f"{datetime.now()}    DEV_EUI: {dev_eui}")
        logger.info(f"{datetime.now()}    JOIN_EUI: {join_eui}")
        logger.info(f"{datetime.now()}    DevNonce: {binascii.hexlify(dev_nonce).decode().upper()}")
        logger.info(f"{datetime.now()}    MIC: {binascii.hexlify(mic).decode().upper()}")
        
        # Verificar si coincide con nuestro dispositivo
        if dev_eui == self.DEV_EUI and join_eui == self.JOIN_EUI:
            logger.info(f"{datetime.now()}  ✓ Dispositivo autorizado, generando Join Accept")
            
            # Crear Join Accept
            join_accept_message = self.create_join_accept(dev_nonce)
            
            logger.info(f"{datetime.now()}  Join Accept creado: {binascii.hexlify(join_accept_message).decode().upper()}")
            
            # Enviar Join Accept con delay apropiado
            self.send_downlink(join_accept_message, rxpk, msg_type=1, delay_ms=5000)
        else:
            logger.info(f"{datetime.now()}  ✗ Dispositivo no autorizado")
            logger.info(f"{datetime.now()}    Esperado DEV_EUI: {self.DEV_EUI}")
            logger.info(f"{datetime.now()}    Esperado JOIN_EUI: {self.JOIN_EUI}")
    
    def handle_unconfirmed_data_up(self, payload, rxpk):
        """Manejar Unconfirmed Data Up"""
        if len(payload) < 12:
            logger.info(f"{datetime.now()}  Payload muy corto para Unconfirmed Data Up")
            return
            
        # Extraer DevAddr (bytes 1-4, little endian)
        dev_addr_bytes = payload[1:5]
        dev_addr = binascii.hexlify(dev_addr_bytes[::-1]).decode().upper()
        
        # Extraer FCtrl y FCnt
        fctrl = payload[5]
        fcnt = int.from_bytes(payload[6:8], 'little')
        
        logger.info(f"{datetime.now()}  📊 Unconfirmed Data Up:")
        logger.info(f"{datetime.now()}    DevAddr: {dev_addr}")
        logger.info(f"{datetime.now()}    FCtrl: 0x{fctrl:02X}")
        logger.info(f"{datetime.now()}    FCnt: {fcnt}")
        
        # Verificar si tenemos una sesión para este dispositivo
        if dev_addr in self.device_sessions:
            session = self.device_sessions[dev_addr]
            logger.info(f"{datetime.now()}    ✓ Sesión encontrada para dispositivo")
            logger.info(f"{datetime.now()}    ✓ FCnt esperado: {session['fcnt_up']}")
            
            # Actualizar contador (simplificado - en producción verificar anti-replay)
            session['fcnt_up'] = max(session['fcnt_up'], fcnt + 1)
            
            # Crear y enviar downlink con el payload especificado
            downlink_frame = self.create_downlink_message(dev_addr, self.DOWNLINK_PAYLOAD)
            if downlink_frame:
                logger.info(f"{datetime.now()}  📤 Enviando downlink automático")
                logger.info(f"{datetime.now()}    Payload: {self.DOWNLINK_PAYLOAD}")
                self.send_downlink(downlink_frame, rxpk)
            else:
                logger.info(f"{datetime.now()}  ❌ Error creando downlink")
        else:
            logger.info(f"{datetime.now()}  ❌ handle_unconfirmed_data_up No hay sesión para el dispositivo: {dev_addr}")
            logger.info(f"{datetime.now()}     Sesiones disponibles: {list(self.device_sessions.keys())}")
    
    def handle_confirmed_data_up(self, payload, rxpk):
        """Manejar Confirmed Data Up"""
        if len(payload) < 12:
            return
            
        # Extraer DevAddr
        dev_addr = binascii.hexlify(payload[1:5][::-1]).decode().upper()
        
        logger.info(f"{datetime.now()}  Confirmed Data Up del dispositivo: {dev_addr}")
        
        # Para Confirmed Data Up, también enviar downlink
        downlink_frame = self.create_downlink_message(dev_addr, self.DOWNLINK_PAYLOAD)
        if downlink_frame:
            logger.info(f"{datetime.now()}  Enviando downlink con payload: {self.DOWNLINK_PAYLOAD}")
            self.send_downlink(downlink_frame, rxpk)
    
    def send_downlink(self, payload, rxpk, msg_type=2, delay_ms=1000):
        """Enviar mensaje downlink al gateway"""
        if not self.gateway_addr:
            logger.info(f"{datetime.now()}  No hay dirección de gateway disponible")
            return
        
        # Para Join Accept, usar RX1 delay
        if msg_type == 1:  # Join Accept
            # Crear estructura de downlink para Join Accept
            txpk = {
                "imme": False,  # No inmediato para Join Accept
                "tmst": rxpk.get('tmst', 0) + delay_ms * 1000,  # Delay en microsegundos
                "freq": 868.5,  # Frecuencia RX1 para EU868
                "rfch": 0,
                "powe": 14,
                "modu": "LORA",
                "datr": rxpk.get('datr', 'SF7BW125'),
                "codr": rxpk.get('codr', '4/5'),
                "ipol": True,
                "size": len(payload),
                "data": binascii.b2a_base64(payload).decode().strip()
            }
        else:
            # Para mensajes normales
            txpk = {
                "imme": True,
                "freq": rxpk.get('freq', 868.1),
                "rfch": 0,
                "powe": 14,
                "modu": "LORA",
                "datr": rxpk.get('datr', 'SF7BW125'),
                "codr": rxpk.get('codr', '4/5'),
                "ipol": True,
                "size": len(payload),
                "data": binascii.b2a_base64(payload).decode().strip()
            }
        
        # Crear mensaje PULL_RESP
        pull_resp = {
            "txpk": txpk
        }
        
        json_data = json.dumps(pull_resp).encode('utf-8')
        
        # Crear paquete completo
        response = bytearray()
        response.append(0x02)  # Protocol version
        response.extend(bytes([0x00, 0x00]))  # Random token
        response.append(0x03)  # PULL_RESP
        response.extend(json_data)
        
        self.sock.sendto(response, self.gateway_addr)
        
        if msg_type == 1:
            logger.info(f"{datetime.now()}  Join Accept enviado: {binascii.hexlify(payload).decode().upper()}")
        else:
            logger.info(f"{datetime.now()}  Downlink enviado: {binascii.hexlify(payload).decode().upper()}")
    
    def run(self):
        """Ejecutar el servidor"""
        logger.info(f"{datetime.now()}  Servidor ejecutándose... Presiona Ctrl+C para detener")
        
        try:
            while True:
                data, addr = self.sock.recvfrom(1024)
                #logger.info(f"{datetime.now()}  Addr: {addr}")                

                if len(data) < 4:
                    continue
                    
                identifier = data[3]
                #logger.info(f"{datetime.now()}  Indetifier: {identifier}")                
                if identifier == 0x00:  # PUSH_DATA
                    self.handle_push_data(data, addr)
                elif identifier == 0x02:  # PULL_DATA
                    self.handle_pull_data(data, addr)
                    
        except KeyboardInterrupt:
            logger.info(f"{datetime.now()}  \nDeteniendo servidor...")
        finally:
            self.sock.close()

def main():
    """Función principal"""
    server = LoRaWANServer()
    server.run()

if __name__ == "__main__":
    main()

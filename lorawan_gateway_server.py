import socket
import json
import struct
import time
import threading
import os
import logging
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

GATEWAY_ID = "AA555A0000000000"
DEV_EUI = "8CF9572000133C5C"   
JOIN_EUI = "8CF9572000000000"  
APP_EUI = JOIN_EUI
APP_KEY = "2B7E151628AED2A6ABF7158809CF4F3C"


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
fh = logging.FileHandler(__file__ + ".log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
fh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.info(f"Situación del log en {os.path.basename(__file__)}")

class SemtechUDPProtocol:
    """Implementa el protocolo UDP Semtech para comunicación con gateways"""
    
    # Tipos de mensaje Semtech
    PUSH_DATA = 0x00
    PUSH_ACK = 0x01
    PULL_DATA = 0x02
    PULL_RESP = 0x03
    PULL_ACK = 0x04
    TX_ACK = 0x05
    
    @staticmethod
    def parse_packet(data):
        """Parsea un paquete UDP Semtech"""
        if len(data) < 4:
            raise ValueError("Paquete demasiado corto")
        
        # Header: version(1) + token(2) + type(1)
        version = data[0]
        token = struct.unpack('>H', data[1:3])[0]
        msg_type = data[3]
        
        result = {
            'version': version,
            'token': token,
            'type': msg_type,
            'payload': None
        }
        
        if msg_type == SemtechUDPProtocol.PUSH_DATA:
            if len(data) < 12:
                raise ValueError("PUSH_DATA demasiado corto")
            # Gateway EUI (8 bytes) + JSON payload
            gateway_eui = data[4:12]
            json_payload = data[12:].decode('utf-8')
            result['gateway_eui'] = gateway_eui
            result['payload'] = json.loads(json_payload)
            
        elif msg_type == SemtechUDPProtocol.PULL_DATA:
            if len(data) < 12:
                raise ValueError("PULL_DATA demasiado corto")
            gateway_eui = data[4:12]
            result['gateway_eui'] = gateway_eui
            
        return result
    
    @staticmethod
    def create_ack(token, msg_type):
        """Crea un paquete ACK"""
        ack_type = {
            SemtechUDPProtocol.PUSH_DATA: SemtechUDPProtocol.PUSH_ACK,
            SemtechUDPProtocol.PULL_DATA: SemtechUDPProtocol.PULL_ACK
        }.get(msg_type)
        
        if ack_type is None:
            raise ValueError(f"No se puede crear ACK para tipo {msg_type}")
        
        # Version 2, token, type
        return struct.pack('>BHB', 2, token, ack_type)
    
    @staticmethod
    def create_pull_resp(token, json_payload):
        """Crea un paquete PULL_RESP para enviar datos al gateway"""
        json_data = json.dumps(json_payload).encode('utf-8')
        header = struct.pack('>BHB', 2, token, SemtechUDPProtocol.PULL_RESP)
        return header + json_data

class LoRaWANJoinRequest:
    def __init__(self):
        self.mhdr = 0x00
        self.appeui = None
        self.deveui = None
        self.devnonce = None
        self.mic = None
    
    @classmethod
    def parse(cls, data):
        if len(data) != 23:
            raise ValueError(f"Join Request debe tener 23 bytes, recibido: {len(data)}")
        
        jr = cls()
        jr.mhdr = data[0]
        
        mtype = (jr.mhdr >> 5) & 0x07
        if mtype != 0:
            raise ValueError(f"No es un Join Request, MTYPE: {mtype}")
        
        jr.appeui = data[1:9][::-1]
        jr.deveui = data[9:17][::-1]
        jr.devnonce = struct.unpack('<H', data[17:19])[0]
        jr.mic = data[19:23]
        
        return jr
    
    def verify_mic(self, appkey):
        msg = bytearray()
        msg.append(self.mhdr)
        msg.extend(self.appeui[::-1])
        msg.extend(self.deveui[::-1])
        msg.extend(struct.pack('<H', self.devnonce))
        
        cipher = CMAC.new(appkey, ciphermod=AES)
        cipher.update(msg)
        calculated_mic = cipher.digest()[:4]
        
        return calculated_mic == self.mic
    
    def __str__(self):
        return (f"Join Request:\n"
                f"  AppEUI: {self.appeui.hex().upper()}\n"
                f"  DevEUI: {self.deveui.hex().upper()}\n"
                f"  DevNonce: {self.devnonce}\n"
                f"  MIC: {self.mic.hex().upper()}")

class LoRaWANJoinAccept:
    def __init__(self):
        self.mhdr = 0x20
        self.appnonce = None
        self.netid = None
        self.devaddr = None
        self.dlsettings = 0
        self.rxdelay = 1
        self.cflist = None
        self.mic = None
    
    def generate_session_keys(self, appkey, appnonce, netid, devnonce):
        base_msg = bytearray(16)
        base_msg[1:4] = appnonce
        base_msg[4:7] = netid
        base_msg[7:9] = struct.pack('<H', devnonce)
        
        # NwkSKey
        nwk_msg = base_msg.copy()
        nwk_msg[0] = 0x01
        cipher = AES.new(appkey, AES.MODE_ECB)
        nwkskey = cipher.encrypt(nwk_msg)
        
        # AppSKey
        app_msg = base_msg.copy()
        app_msg[0] = 0x02
        cipher = AES.new(appkey, AES.MODE_ECB)
        appskey = cipher.encrypt(app_msg)
        
        return nwkskey, appskey
    
    def encrypt_payload(self, appkey):
        payload = bytearray()
        payload.extend(self.appnonce)
        payload.extend(self.netid)
        payload.extend(struct.pack('<I', self.devaddr))
        payload.append(self.dlsettings)
        payload.append(self.rxdelay)
        
        if self.cflist:
            payload.extend(self.cflist)
        
        # Calcular MIC
        mic_msg = bytearray([self.mhdr]) + payload
        cipher = CMAC.new(appkey, ciphermod=AES)
        cipher.update(mic_msg)
        self.mic = cipher.digest()[:4]
        
        payload.extend(self.mic)
        
        # Encriptar
        cipher = AES.new(appkey, AES.MODE_ECB)
        while len(payload) % 16 != 0:
            payload.append(0)
        
        encrypted_payload = bytearray()
        for i in range(0, len(payload), 16):
            block = payload[i:i+16]
            encrypted_block = cipher.encrypt(block)
            encrypted_payload.extend(encrypted_block)
        
        return bytes([self.mhdr]) + encrypted_payload

class LoRaWANNetworkServer:
    def __init__(self, host='0.0.0.0', port=1700):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
        # Base de datos de dispositivos
        self.devices = {
            bytes.fromhex(DEV_EUI): {
                "appeui": bytes.fromhex(APP_EUI),
                "appkey": bytes.fromhex(APP_KEY),
                "last_devnonce": 0
            }
        }
        
        self.active_sessions = {}
        self.gateways = {}  # Gateway EUI -> {last_seen, stats, addr}
        '''
        self.gateways[GATEWAY_ID].update({
            'last_seen': time.time(),
            'addr': addr,
            'pull_token': packet['token']
        })
        '''
        
    def start(self):
        """Inicia el servidor"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        logger.info(f"{datetime.now()} 🚀 Servidor LoRaWAN iniciado en {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                threading.Thread(
                    target=self.handle_packet,
                    args=(data, addr),
                    daemon=True
                ).start()
                
            except Exception as e:
                if self.running:
                    logger.info(f"{datetime.now()} ❌ Error recibiendo datos: {e}")
    
    def handle_packet(self, data, addr):
        """Maneja un paquete UDP del gateway"""
        try:
            packet = SemtechUDPProtocol.parse_packet(data)
            
            if packet['type'] == SemtechUDPProtocol.PUSH_DATA:
                self.handle_push_data(packet, addr)
                
            elif packet['type'] == SemtechUDPProtocol.PULL_DATA:
                self.handle_pull_data(packet, addr)
                
        except Exception as e:
            logger.info(f"{datetime.now()} ❌ Error procesando paquete de {addr}: {e}")
    
    def handle_push_data(self, packet, addr):
        """Maneja PUSH_DATA (datos del gateway)"""
        gateway_eui = packet['gateway_eui'].hex().upper()
        #logger.info(f"{datetime.now()} 📡 PUSH_DATA Packet {packet}")
        # Enviar ACK
        ack = SemtechUDPProtocol.create_ack(packet['token'], packet['type'])
        self.socket.sendto(ack, addr)
        
        # Actualizar info del gateway
        self.gateways[gateway_eui] = {
            'last_seen': time.time(),
            'addr': addr,
            'stats': packet['payload'].get('stat', {})
        }
        
        logger.info(f"{datetime.now()} 📡 PUSH_DATA de gateway {gateway_eui} desde {addr}")
        
        # Procesar mensajes LoRaWAN si los hay
        if 'rxpk' in packet['payload']:
            for rxpk in packet['payload']['rxpk']:
                self.process_lorawan_message(rxpk, gateway_eui)
    
    def handle_pull_data(self, packet, addr):
        """Maneja PULL_DATA (gateway solicitando datos)"""
        gateway_eui = packet['gateway_eui'].hex().upper()
        #logger.info(f"{datetime.now()} 📥  PULL_DATA Packet {packet}")
        # Enviar ACK
        ack = SemtechUDPProtocol.create_ack(packet['token'], packet['type'])
        self.socket.sendto(ack, addr)
        
        # Actualizar info del gateway
        if gateway_eui not in self.gateways:
            self.gateways[gateway_eui] = {}
        
        self.gateways[gateway_eui].update({
            'last_seen': time.time(),
            'addr': addr,
            'pull_token': packet['token']
        })
        
        logger.info(f"{datetime.now()} 📥 PULL_DATA de gateway {gateway_eui} desde {addr}")
    
    def process_lorawan_message(self, rxpk, gateway_eui):
        """Procesa un mensaje LoRaWAN recibido"""
        try:
            # Decodificar payload base64
            import base64
            lorawan_data = base64.b64decode(rxpk['data'])
            
            logger.info(f"{datetime.now()} \n📨 Mensaje LoRaWAN recibido de gateway {gateway_eui}:")
            logger.info(f"{datetime.now()}    Frecuencia: {rxpk.get('freq', 'N/A')} MHz")
            logger.info(f"{datetime.now()}    RSSI: {rxpk.get('rssi', 'N/A')} dBm")
            logger.info(f"{datetime.now()}    SNR: {rxpk.get('lsnr', 'N/A')} dB")
            logger.info(f"{datetime.now()}    Payload: {lorawan_data.hex().upper()}")
            
            # Verificar tipo de mensaje
            mhdr = lorawan_data[0]
            mtype = (mhdr >> 5) & 0x07
            
            if mtype == 0:  # Join Request
                self.handle_join_request(lorawan_data, rxpk, gateway_eui)
            else:
                logger.info(f"{datetime.now()}    Tipo de mensaje: {mtype} (no implementado)")
                
        except Exception as e:
            logger.info(f"{datetime.now()} ❌ Error procesando mensaje LoRaWAN: {e}")
    
    def handle_join_request(self, data, rxpk, gateway_eui):
        """Maneja un Join Request"""
        try:
            # Parsear Join Request
            jr = LoRaWANJoinRequest.parse(data)
            logger.info(f"{datetime.now()}    {jr}")
            
            # Buscar dispositivo
            device = self.devices.get(jr.deveui)
            if not device:
                logger.info(f"{datetime.now()}    ❌ Dispositivo no encontrado")
                return
            
            # Verificar AppEUI y MIC
            if device["appeui"] != jr.appeui:
                logger.info(f"{datetime.now()}    ❌ AppEUI no coincide")
                return
            
            if not jr.verify_mic(device["appkey"]):
                logger.info(f"{datetime.now()}    ❌ MIC inválido")
                return
            
            # Verificar DevNonce
            if jr.devnonce <= device["last_devnonce"]:
                logger.info(f"{datetime.now()}    ❌ DevNonce replay")
                return
            
            logger.info(f"{datetime.now()}    ✅ Join Request válido")
            
            # Generar Join Accept
            ja = LoRaWANJoinAccept()
            ja.appnonce = os.urandom(3)
            ja.netid = bytes([0x00, 0x00, 0x01])
            ja.devaddr = struct.unpack('<I', os.urandom(4))[0] & 0x01FFFFFF
            
            # Generar claves de sesión
            nwkskey, appskey = ja.generate_session_keys(
                device["appkey"], ja.appnonce, ja.netid, jr.devnonce
            )
            
            # Actualizar estado
            device["last_devnonce"] = jr.devnonce
            self.active_sessions[ja.devaddr] = {
                "deveui": jr.deveui,
                "nwkskey": nwkskey,
                "appskey": appskey,
                "fcnt_up": 0,
                "fcnt_down": 0
            }
            
            # Encriptar Join Accept
            encrypted_ja = ja.encrypt_payload(device["appkey"])
            
            logger.info(f"{datetime.now()}    📤 Enviando Join Accept:")
            logger.info(f"{datetime.now()}       DevAddr: 0x{ja.devaddr:08X}")
            logger.info(f"{datetime.now()}       Payload: {encrypted_ja.hex().upper()}")
            
            # Enviar Join Accept al gateway
            self.send_downlink(encrypted_ja, rxpk, gateway_eui)
            
        except Exception as e:
            logger.info(f"{datetime.now()}    ❌ Error procesando Join Request: {e}")
    


    def send_downlink(self, payload, rxpk, gateway_eui):
        """Envía un mensaje downlink al gateway"""
        try:
            gateway_info = self.gateways.get(gateway_eui)
            if not gateway_info or 'pull_token' not in gateway_info:
                logger.info(f"{datetime.now()}    ❌ Gateway {gateway_eui} no disponible para downlink")
                return
            
            import base64
            
            # Crear mensaje de respuesta
            # RX1: 1 segundo después, misma frecuencia
            tmst_rx1 = rxpk['tmst'] + 1000000  # +1 segundo
            
            # RX2: 2 segundos después, frecuencia fija (869.525 MHz EU868)
            tmst_rx2 = rxpk['tmst'] + 2000000  # +2 segundos
            
            # Preparar el downlink (usando RX1)
            txpk = {
                "imme": False,
                "tmst": tmst_rx1,
                "freq": rxpk['freq'],  # Misma frecuencia que uplink
                "rfch": 0,
                "powe": 14,
                "modu": "LORA",
                "datr": rxpk['datr'],  # Mismo data rate
                "codr": rxpk['codr'],  # Mismo coding rate
                "ipol": True,
                "size": len(payload),
                "data": base64.b64encode(payload).decode('ascii')
            }
            
            pull_resp_payload = {
                "txpk": txpk
            }
            
            # Crear paquete PULL_RESP
            pull_resp = SemtechUDPProtocol.create_pull_resp(
                gateway_info['pull_token'], 
                pull_resp_payload
            )
            
            # Enviar al gateway
            self.socket.sendto(pull_resp, gateway_info['addr'])
            logger.info(f"{datetime.now()}    📡 Join Accept enviado a gateway {gateway_eui}")
            
        except Exception as e:
            logger.info(f"{datetime.now()}    ❌ Error enviando downlink: {e}")
    
    def stop(self):
        """Detiene el servidor"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("🛑 Servidor detenido")
    
    def show_status(self):
        """Muestra el estado del servidor"""
        print("\n📊 Estado del servidor:")
        logger.info(f"{datetime.now()}    Gateways conectados: {len(self.gateways)}")
        for gw_eui, info in self.gateways.items():
            last_seen = datetime.fromtimestamp(info['last_seen']).strftime('%H:%M:%S')
            logger.info(f"{datetime.now()}      {gw_eui}: último contacto {last_seen}")
        
        logger.info(f"{datetime.now()}    Sesiones activas: {len(self.active_sessions)}")
        for devaddr, session in self.active_sessions.items():
            logger.info(f"{datetime.now()}      0x{devaddr:08X}: {session['deveui'].hex().upper()}")

# Ejemplo de uso
if __name__ == "__main__":
    server = LoRaWANNetworkServer()
    
    try:
        # Mostrar estado cada 30 segundos
        def status_thread():
            while server.running:
                time.sleep(30)
                if server.running:
                    server.show_status()
        
        threading.Thread(target=status_thread, daemon=True).start()
        
        # Iniciar servidor
        server.start()
        
    except KeyboardInterrupt:
        print("\n🛑 Deteniendo servidor...")
        server.stop()

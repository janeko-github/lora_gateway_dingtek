import socket
import struct
import json
import threading
import time
import binascii
import logging
import base64
import os
from datetime import datetime

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
fh = logging.FileHandler(__file__+".log")
fh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.info(f"Situación del log en {os.path.basename(__file__)}")


class LoRaWANMessageTypes:
    """Constantes para tipos de mensajes LoRaWAN"""
    JOIN_REQUEST = 0x00
    JOIN_ACCEPT = 0x20
    UNCONFIRMED_DATA_UP = 0x40
    UNCONFIRMED_DATA_DOWN = 0x60
    CONFIRMED_DATA_UP = 0x80
    CONFIRMED_DATA_DOWN = 0xA0
    REJOIN_REQUEST = 0xC0

class LoRaWANGateway:
    def __init__(self, gateway_id, dev_eui, join_eui, app_key, port=1700):
        self.gateway_id = gateway_id
        self.dev_eui = dev_eui.lower()
        self.join_eui = join_eui.lower()
        self.app_key = app_key.lower()
        self.port = port
        self.sock = None
        self.running = False
        self.downlink_counter = 0
        
        # Protocolo Semtech
        self.PUSH_DATA = 0
        self.PUSH_ACK = 1
        self.PULL_DATA = 2
        self.PULL_RESP = 3
        self.PULL_ACK = 4
        self.TX_ACK = 5
        
    def start(self):
        """Inicia el servidor UDP"""
        logger.info(f"{datetime.now()} Inicia el servidor UDP")
        try:
            
            logger.info(f"{datetime.now()} Creando socket")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('localhost', self.port))
            self.running = True
            
            logger.info(f"{datetime.now()} Escuchando en puerto {self.port}")
            
            # Hilo para enviar PULL_DATA periódicamente
            pull_thread = threading.Thread(target=self.send_pull_data)
            pull_thread.daemon = True
            pull_thread.start()
            
            # Hilo principal para recibir mensajes
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Mantener el programa corriendo
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("{datetime.now()} Deteniendo servidor...")
                self.stop()
                
        except Exception as e:
            logger.error(f"{datetime.now()}  Error al iniciar el servidor: {e}")
            
    def stop(self):
        """Detiene el servidor"""
        logger.info(f"{datetime.now()} Detiene el servidor UDP")
        self.running = False
        if self.sock:
            self.sock.close()
            
    def send_pull_data(self):
        """Envía mensaje PULL_DATA cada 5 segundos"""
        logger.info(f"{datetime.now()} Envía mensaje PULL_DATA cada 5 segundos")
        while self.running:
            try:
                # Crear mensaje PULL_DATA
                token = struct.pack('>H', int(time.time()) & 0xFFFF)  # Token basado en tiempo
                gateway_id_bytes = binascii.unhexlify(self.gateway_id)
                message = struct.pack('B', self.PULL_DATA) + token + gateway_id_bytes
                
                self.sock.sendto(message, ('localhost', self.port))
                logger.debug("PULL_DATA enviado")
                time.sleep(5)  # Enviar cada 5 segundos
            except Exception as e:
                logger.error(f"{datetime.now()} Error enviando PULL_DATA: {e}")
                
    def receive_messages(self):
        """Recibe y procesa mensajes"""
        logger.info(f"{datetime.now()} Recibe y procesa mensajes")
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                self.process_message(data, addr)
            except socket.error:
                if self.running:
                    logger.error("Error de socket")
                break
            except Exception as e:
                logger.error(f"Error procesando mensaje: {e}")
                
    def process_message(self, data, addr):
        """Procesa los mensajes recibidos"""
        logger.info(f"{datetime.now()} Procesa los mensajes recibidos")
        if len(data) < 4:
            return
            
        msg_type = data[0]
        token = data[1:3]
        
        # Enviar ACK para PUSH_DATA
        if msg_type == self.PUSH_DATA:
            self.send_push_ack(token, addr)
            if len(data) > 12:
                self.handle_push_data(data, addr)
                
        elif msg_type == self.PULL_ACK:
            logger.debug("Recibido PULL_ACK")
            
    def send_push_ack(self, token, addr):
        """Envía PUSH_ACK como respuesta a PUSH_DATA"""
        logger.info(f"{datetime.now()} Envía PUSH_ACK como respuesta a PUSH_DATA")
        try:
            message = struct.pack('B', self.PUSH_ACK) + token
            self.sock.sendto(message, addr)
        except Exception as e:
            logger.error(f"Error enviando PUSH_ACK: {e}")
            
    def handle_push_data(self, data, addr):
        """Maneja mensajes PUSH_DATA"""
        logger.info(f"{datetime.now()} Maneja mensajes PUSH_DATA")
        try:
            # Extraer JSON del mensaje
            json_data = data[12:].decode('utf-8')
            payload = json.loads(json_data)
            
            logger.info(f"Mensaje PUSH_DATA recibido: {payload}")
            
            # Procesar diferentes tipos de mensajes
            self.process_lorawan_message(payload, addr)
            
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"No se pudo decodificar el payload JSON: {e}")
        except Exception as e:
            logger.error(f"Error manejando PUSH_DATA: {e}")
            
    def process_lorawan_message(self, payload, addr):
        """Procesa diferentes tipos de mensajes LoRaWAN"""
        logger.info(f"{datetime.now()} Procesa diferentes tipos de mensajes LoRaWAN")
        try:
            if 'rxpk' in payload and len(payload['rxpk']) > 0:
                for rxpk in payload['rxpk']:
                    if rxpk.get('stat') == 'CRC_OK':  # Mensaje válido
                        # Decodificar el payload base64
                        if 'data' in rxpk:
                            data_b64 = rxpk['data']
                            data_bytes = base64.b64decode(data_b64)
                            
                            if len(data_bytes) > 0:
                                mtype = data_bytes[0] & 0xE0  # Primer 3 bits son MType
                                logger.info(f"Tipo de mensaje detectado: 0x{mtype:02X}")
                                
                                # Determinar y procesar el tipo de mensaje
                                if mtype == LoRaWANMessageTypes.UNCONFIRMED_DATA_UP:
                                    self.handle_unconfirmed_data_up(payload, rxpk, addr)
                                elif mtype == LoRaWANMessageTypes.UNCONFIRMED_DATA_DOWN:
                                    self.handle_unconfirmed_data_down(payload, rxpk, addr)
                                elif mtype == LoRaWANMessageTypes.CONFIRMED_DATA_UP:
                                    self.handle_confirmed_data_up(payload, rxpk, addr)
                                elif mtype == LoRaWANMessageTypes.CONFIRMED_DATA_DOWN:
                                    self.handle_confirmed_data_down(payload, rxpk, addr)
                                elif mtype == LoRaWANMessageTypes.JOIN_REQUEST:
                                    self.handle_join_request(payload, rxpk, addr)
                                elif mtype == LoRaWANMessageTypes.REJOIN_REQUEST:
                                    self.handle_rejoin_request(payload, rxpk, addr)
                                    
        except Exception as e:
            logger.error(f"Error procesando mensaje LoRaWAN: {e}")
            
    def handle_unconfirmed_data_up(self, payload, rxpk, addr):
        """Maneja mensajes UnconfirmedDataUp"""
        logger.info(f"{datetime.now()} Procesa mensajes UnconfirmedDataUp")
        logger.info("✓ UnconfirmedDataUp detectado")
        dev_eui = self.extract_dev_eui_from_payload(rxpk)
        logger.info(f"  DevEUI: {dev_eui}")
        
        # Enviar downlink de respuesta
        self.send_downlink(addr, rxpk, "80029999010A81",True) # 0 horas
        
    def handle_unconfirmed_data_down(self, payload, rxpk, addr):
        """Maneja mensajes UnconfirmedDataDown"""
        logger.info(f"{datetime.now()} Procesa mensajes UnconfirmedDataDown")
        logger.info("✓ UnconfirmedDataDown detectado")
        dev_eui = self.extract_dev_eui_from_payload(rxpk)
        logger.info(f"  DevEUI: {dev_eui}")
        
    def handle_confirmed_data_up(self, payload, rxpk, addr):
        """Maneja mensajes ConfirmedDataUp"""
        logger.info(f"{datetime.now()} Procesa mensajes ConfirmedDataUp")
        logger.info("✓ ConfirmedDataUp detectado")
        dev_eui = self.extract_dev_eui_from_payload(rxpk)
        logger.info(f"  DevEUI: {dev_eui}")
        
        # Enviar ACK como respuesta
        self.send_downlink(addr, rxpk, "ConfirmedDataUp ACK")
        
    def handle_confirmed_data_down(self, payload, rxpk, addr):
        """Maneja mensajes ConfirmedDataDown"""
        logger.info(f"{datetime.now()} Procesa mensajes ConfirmedDataDown")
        logger.info("✓ ConfirmedDataDown detectado")
        dev_eui = self.extract_dev_eui_from_payload(rxpk)
        logger.info(f"  DevEUI: {dev_eui}")
        
    def handle_join_request(self, payload, rxpk, addr):
        """Maneja mensajes JoinRequest"""
        logger.info(f"{datetime.now()} Procesa mensajes JoinRequest")
        logger.info("✓ JoinRequest detectado")
        try:
            data_b64 = rxpk['data']
            data_bytes = base64.b64decode(data_b64)
            
            if len(data_bytes) >= 19:  # JoinRequest tiene al menos 19 bytes
                join_eui = data_bytes[1:9][::-1]  # 8 bytes invertidos
                dev_eui = data_bytes[9:17][::-1]  # 8 bytes invertidos
                dev_nonce = data_bytes[17:19]     # 2 bytes
                
                join_eui_hex = binascii.hexlify(join_eui).decode()
                dev_eui_hex = binascii.hexlify(dev_eui).decode()
                dev_nonce_hex = binascii.hexlify(dev_nonce).decode()
                
                logger.info(f"  JoinEUI: {join_eui_hex}")
                logger.info(f"  DevEUI: {dev_eui_hex}")
                logger.info(f"  DevNonce: {dev_nonce_hex}")
                
                # Enviar JoinAccept si coincide con nuestro dispositivo
                if dev_eui_hex.lower() == self.dev_eui.lower():
                    self.send_join_accept(addr, rxpk, dev_nonce_hex)
                    
        except Exception as e:
            logger.error(f"Error procesando JoinRequest: {e}")
            
    def handle_rejoin_request(self, payload, rxpk, addr):
        """Maneja mensajes RejoinRequest"""
        logger.info(f"{datetime.now()} Procesa mensajes RejoinRequest")
        logger.info("✓ RejoinRequest detectado")
        dev_eui = self.extract_dev_eui_from_payload(rxpk)
        logger.info(f"  DevEUI: {dev_eui}")
        
    def handle_join_accept(self, payload, rxpk, addr):
        """Maneja mensajes JoinAccept"""
        logger.info(f"{datetime.now()} Procesa mensajes JoinAccept")
        logger.info("✓ JoinAccept detectado")
        # JoinAccept normalmente va en downlink, este método es para registro
        
    def extract_dev_eui_from_payload(self, rxpk):
        """Extrae DevEUI del payload (simplificado)"""
        logger.info(f"{datetime.now()} Extrae DevEUI del payload (simplificado)")
        try:
            # En mensajes reales, el DevEUI puede estar en diferentes posiciones
            # Esta es una implementación básica
            return self.dev_eui
        except:
            return "Desconocido"
            
    def send_join_accept(self, addr, rxpk, dev_nonce):
        """Envía mensaje JoinAccept"""
        logger.info(f"{datetime.now()} Envía mensaje JoinAccept")
        try:
            logger.info("Enviando JoinAccept...")
            
            # Payload JoinAccept simulado (en producción necesitarías implementar
            # el cifrado real con la AppKey)
            join_accept_payload = "20" + "00112233445566778899aabbccddeeff"  # Header + AppNonce + NetID + DevAddr
            
            self.send_downlink(addr, rxpk, join_accept_payload, is_hex=True)
            
        except Exception as e:
            logger.error(f"Error enviando JoinAccept: {e}")
            
    def send_downlink(self, addr, rxpk, payload_data, is_hex=False):
        """Envía mensaje downlink al dispositivo"""
        logger.info(f"{datetime.now()} Envía mensaje downlink al dispositivo")
        logger.info("Enviando JoinAccept...")

        try:
            # Preparar payload
            if is_hex:
                payload_hex = payload_data
            else:
                # Convertir string a hexadecimal
                payload_bytes = payload_data.encode('utf-8')
                payload_hex = binascii.hexlify(payload_bytes).decode()
            
            # Crear mensaje PULL_RESP
            response_data = {
                "txpk": {
                    "imme": True,
                    "freq": rxpk.get('freq', 868.1),
                    "rfch": 0,
                    "powe": 14,
                    "modu": rxpk.get('modu', 'LORA'),
                    "datr": rxpk.get('datr', 'SF7BW125'),
                    "codr": rxpk.get('codr', '4/5'),
                    "ipol": True,
                    "size": len(binascii.unhexlify(payload_hex)),
                    "data": payload_hex,
                    "brd": rxpk.get('brd', 0),  # Antenna ID
                    "ant": rxpk.get('ant', 0)   # Antenna ID
                }
            }
            
            # Generar token único
            token = struct.pack('>H', (self.downlink_counter % 65536))
            self.downlink_counter += 1
            
            json_str = json.dumps(response_data)
            json_bytes = json_str.encode('utf-8')
            
            # Construir mensaje completo
            message = struct.pack('B', self.PULL_RESP) + token + json_bytes
            
            # Enviar mensaje
            self.sock.sendto(message, addr)
            logger.info(f"Downlink enviado: {payload_data}")
            logger.debug(f"Payload hex: {payload_hex}")
            
        except Exception as e:
            logger.error(f"Error enviando downlink: {e}")

def main():

    GATEWAY_ID = "AA555A0000000000"  # ID de la pasarela (16 caracteres hex) nuestro RAK de la oficina
    # Residuos 4281 deveui 8CF9572000133C5C
    # Residuos deveui 8CF957200016290F
    # Residuos deveui 8CF9572000059A3D
    DEV_EUI = "8CF9572000133C5C"     # DevEUI del dispositivo
    JOIN_EUI = "8CF9572000000000"   # JoinEUI/AppEUI
    APP_KEY = "2B7E151628AED2A6ABF7158809CF4F3C"  # AppKey (32 caracteres hex)    
    # Crear e iniciar la pasarela
    gateway = LoRaWANGateway(
        gateway_id=GATEWAY_ID,
        dev_eui=DEV_EUI,
        join_eui=JOIN_EUI,
        app_key=APP_KEY
    )
    
    try:
        gateway.start()
    except KeyboardInterrupt:
        logger.info("Aplicación detenida por el usuario")
    except Exception as e:
        logger.error(f"Error en la aplicación: {e}")

if __name__ == "__main__":
    main()

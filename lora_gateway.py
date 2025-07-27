'''
    Asegúrate de que lora_pkt_fwd esté ejecutándose
    Ejecuta esta aplicación: python3 lora_gateway.py
    El sistema detectará mensajes UnconfirmedDataUp y responderá automáticamente
     
    Escucha el puerto 1700 para comunicarse con lora_pkt_fwd 

    Maneja el protocolo Semtech (PUSH_DATA, PULL_DATA, PULL_RESP, etc.) 

    Identificadores parametrizables: 
        Gateway ID
        DevEUI del dispositivo
        JoinEUI/AppEUI
        AppKey
         

    Funcionalidad de downlink: 
        Detecta mensajes UnconfirmedDataUp
        Envía respuesta automática con payload personalizable
         
     

La aplicación incluye logging para facilitar el debugging y monitoreo de la comunicación. 

Cambiar estos parámetros
GATEWAY_ID = "tu_gateway_id_hex"
DEV_EUI = "dev_eui_dispositivo"
JOIN_EUI = "join_eui_app_eui"
APP_KEY = "app_key_32_caracteres"

y ajustar, si hace falta, que no
"datr": "SF7BW125",   # Data rate 12 pa má lento
"powe": 14,           # Potencia



'''
import socket
import struct
import json
import threading
import time
import binascii
import logging
from datetime import datetime

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
fh = logging.FileHandler(__file__+".log")
fh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.info(f"Situación del log en {os.path.basename(__file__)}")


class LoRaWANGateway:
    def __init__(self, gateway_id, dev_eui, join_eui, app_key, port=1700):
        self.gateway_id = gateway_id
        self.dev_eui = dev_eui.lower()
        self.join_eui = join_eui.lower()
        self.app_key = app_key.lower()
        self.port = port
        self.sock = None
        self.running = False
        
        # Protocolo Semtech
        self.PUSH_DATA = 0
        self.PUSH_ACK = 1
        self.PULL_DATA = 2
        self.PULL_RESP = 3
        self.PULL_ACK = 4
        self.TX_ACK = 5
        
    def start(self):
        """Inicia el servidor UDP"""
        try:
            logger.info(f"Iniciando el socket de los coxones")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('localhost', self.port))
            self.running = True
            
            logger.info(f"Escuchando en puerto {self.port}")
            logger.info(f"Escuchando en puerto {self.port}")

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
                logger.info("Deteniendo servidor...")
                self.stop()
                
        except Exception as e:
            logger.error(f"Error al iniciar el servidor: {e}")
            
    def stop(self):
        """Detiene el servidor"""
        self.running = False
        if self.sock:
            self.sock.close()
            
    def send_pull_data(self):
        """Envía mensaje PULL_DATA cada 5 segundos"""
        while self.running:
            try:
                # Crear mensaje PULL_DATA
                logger.info(f" {datetime.now()} Enviando PULL_DATA")
                token = struct.pack('>H', 0x1234)  # Token de ejemplo
                gateway_id_bytes = binascii.unhexlify(self.gateway_id)
                message = struct.pack('B', self.PULL_DATA) + token + gateway_id_bytes
                
                self.sock.sendto(message, ('localhost', self.port))
                time.sleep(5)  # Enviar cada 5 segundos
            except Exception as e:
                logger.error(f"Error enviando PULL_DATA: {e}")
                
    def receive_messages(self):
        """Recibe y procesa mensajes"""
        while self.running:
            try:
                logger.info(f" {datetime.now()} Recibiendo mensaje")
                data, addr = self.sock.recvfrom(1024)
                self.process_message(data, addr)
            except socket.error:
                if self.running:
                    logger.error("Error de socket")
                break
            except Exception as e:
                logger.error(f"Error procesando mensaje: {e}")
                
    def process_message(self, data, addr):
        """Procesa los mensajes recibidos"""
        if len(data) < 4:
            return
            
        msg_type = data[0]
        token = data[1:3]
        
        if msg_type == self.PUSH_DATA and len(data) > 12:
            # Procesar PUSH_DATA (mensajes del dispositivo)
            logger.info(f" {datetime.now()} Mensaje del dispositivo")
            try:
                # Extraer JSON del mensaje
                json_data = data[12:].decode('utf-8')
                payload = json.loads(json_data)
                
                logger.info(f"Mensaje recibido: {payload}")
                
                # Verificar si es UnconfirmedDataUp
                if self.is_unconfirmed_data_up(payload):
                    self.send_downlink(token, addr, payload)
                    
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("No se pudo decodificar el payload JSON")
                
        elif msg_type == self.PULL_ACK:
            logger.debug("Recibido PULL_ACK")
            
    def is_unconfirmed_data_up(self, payload):
        """Verifica si el mensaje es UnconfirmedDataUp"""
        try:
            # Verificar estructura del mensaje
            if 'rxpk' in payload:
                for rxpk in payload['rxpk']:
                    if rxpk.get('stat') == 'OK':  # Mensaje válido
                        return True
            return False
        except Exception as e:
            logger.error(f"Error verificando tipo de mensaje: {e}")
            return False
            
    def send_downlink(self, token, addr, payload):
        """Envía mensaje downlink al dispositivo"""
        logger.info(f" {datetime.now()} Downlink")
        try:
            # Extraer información del dispositivo
            dev_eui = None
            if 'rxpk' in payload and len(payload['rxpk']) > 0:
                # Aquí podrías extraer el DevEUI del mensaje si está disponible
                pass
                
            # Payload de ejemplo para el downlink (puedes personalizarlo)
            downlink_payload = "48656c6c6f"  # "Hello" en hexadecimal
            
            # Crear mensaje PULL_RESP
            response_data = {
                "txpk": {
                    "imme": True,
                    "freq": 868.1,
                    "rfch": 0,
                    "powe": 14,
                    "modu": "LORA",
                    "datr": "SF7BW125",
                    "codr": "4/5",
                    "ipol": True,
                    "size": len(binascii.unhexlify(downlink_payload)),
                    "data": downlink_payload,
                    "devEUI": self.dev_eui
                }
            }
            
            json_str = json.dumps(response_data)
            json_bytes = json_str.encode('utf-8')
            
            # Construir mensaje completo
            message = struct.pack('B', self.PULL_RESP) + token + json_bytes
            
            # Enviar mensaje
            self.sock.sendto(message, addr)
            logger.info(f"Downlink enviado al dispositivo {self.dev_eui}")
            logger.debug(f"Payload: {downlink_payload}")
            
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

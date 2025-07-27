import socket
import struct
import threading
import json
import time
import logging
from datetime import datetime
from Crypto.Cipher import AES
import binascii
import os


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configuración de identificadores
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



class LoRaWANServer:
    def __init__(self, host='localhost', port=1700):
        self.host = host
        self.port = port
        self.sock = None
        self.gateway_id = bytes.fromhex(GATEWAY_ID)
        self.dev_eui = bytes.fromhex(DEV_EUI)
        self.join_eui = bytes.fromhex(JOIN_EUI)
        self.app_key = bytes.fromhex(APP_KEY)
        
    def start_server(self):
        """Inicia el servidor UDP para escuchar en el puerto 1700"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            logger.info(f"{datetime.now()} Servidor iniciado en {self.host}:{self.port}")
            
            while True:
                data, addr = self.sock.recvfrom(1024)
                #PHYPayload = MHDR | MACPayload | MIC
                '''
                    MHDR (1 byte): Tipo de mensaje (MType), RFU, Major.
                    MACPayload: Contiene el FHDR, FPort y FRMPayload.
                    MIC (4 bytes): Código de integridad del mensaje.
                '''
                #logger.info(f"{datetime.now()} Datos recibidos de addr: {addr} ip: {addr[0]} port: {addr[1]}")
                #logger.info(f"{datetime.now()} Datos recibidos de data: {data}")
                
                # Procesar el mensaje en un hilo separado
                threading.Thread(target=self.process_message, args=(data, addr)).start()
                
        except Exception as e:
            logger.error(f"{datetime.now()} Error en el servidor: {e}")
        finally:
            if self.sock:
                self.sock.close()

    def derive_app_skey(self, dev_nonce: bytes):
        # Crear el nonce para derivar la clave
        nonce = bytearray(16)
        nonce[0] = 0x02  # Para AppSKey
        nonce[1:9] = JOIN_EUI[::-1]   # AppEUI invertido
        nonce[9:13] = dev_nonce       # DevNonce
        nonce[13:17] = DEV_EUI[::-1]  # DevEUI invertido
        
        # AES-128 encrypt
        cipher = Cipher(algorithms.AES(APP_KEY), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        app_skey = encryptor.update(bytes(nonce)) + encryptor.finalize()
        
        return app_skey

                
    def decrypt_frm_payload(self,frm_payload: bytes, key: bytes, dev_addr: bytes, fcnt: int, uplink: bool):
        """
        Descifra el FRMPayload usando AES-CTR.
        """
        # Crear el nonce (16 bytes)
        nonce = bytearray(16)
        nonce[0] = 0x01 if uplink else 0x02
        nonce[1:5] = dev_addr[::-1]  # DevAddr en orden inverso
        nonce[5:9] = fcnt.to_bytes(4, byteorder='little')
        nonce[9] = 0x00  # 0x00 para datos

        # Crear cipher AES-CTR
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(frm_payload) + decryptor.finalize()

        return decrypted

    def parse_lorawan_packet(self,data: bytes):
        # MHDR (1 byte)
        mhdr = data[0]
        logger.info(f"{datetime.now()} MHDR explain {bin(mhdr)[2:]}") 
        mtype = (mhdr >> 5) #& 0x07
        major = mhdr & 0x03
 
    
        mtype_names = {
            0: "Join Request",
            1: "Join Accept",
            2: "Unconfirmed Data Up",
            3: "Unconfirmed Data Down",
            4: "Confirmed Data Up",
            5: "Confirmed Data Down"
        }

        logger.info(f"{datetime.now()} MHDR: 0x{mhdr:02x}")
        logger.info(f"{datetime.now()} MType: {mtype} ({mtype_names.get(mtype, 'Unknown')})")
        logger.info(f"{datetime.now()} Major: {major}")

        # MIC (últimos 4 bytes)
        mic = data[-4:]
        logger.info(f"{datetime.now()} MIC: {mic.hex()}")

        # MACPayload (entre MHDR y MIC)
        mac_payload = data[1:-4]
        #logger.info(f"{datetime.now()} MACPayload (hex): {mac_payload.hex()}")
        self.parse_mac_payload(mac_payload)

    def parse_mac_payload(self,mac_payload: bytes):
        # FHDR: DevAddr (4) + FCtrl (1) + FCnt (2) + FOpts (0-15)
        dev_addr = mac_payload[0:4][::-1]  # invertir orden
        fctrl = mac_payload[4]
        fcnt = int.from_bytes(mac_payload[5:7], byteorder='little')
        fopts_len = fctrl & 0x0F
        fopts = mac_payload[7:7+fopts_len]
        rest = mac_payload[7+fopts_len:]

        logger.info(f"{datetime.now()} DevAddr: {dev_addr.hex()}")
        logger.info(f"{datetime.now()} FCtrl: 0x{fctrl:02x}")
        logger.info(f"{datetime.now()} FCnt: {fcnt}")
        logger.info(f"{datetime.now()} FOpts: {fopts.hex()}")

        if len(rest) > 0:
            fport = rest[0]
            frm_payload = rest[1:]
            logger.info(f"{datetime.now()} FPort: {fport}")
            logger.info(f"{datetime.now()} FRMPayload Longitud: {len(frm_payload.hex()) / 2 } bytes")
            logger.info(f"{datetime.now()} FRMPayload: {frm_payload.hex()}")
            app_skey = derive_app_skey(self, dev_nonce)
            # Descifrar FRMPayload
            uplink = True  # ajustar según el tipo de mensaje
            try:
                decrypted = self.decrypt_frm_payload(frm_payload, app_skey, dev_addr, fcnt, uplink)
                logger.info(f"{datetime.now()} FRMPayload (descifrado): {decrypted.hex()} | ASCII: {decrypted.decode('utf-8', errors='ignore')}")
            except Exception as e:
                logger.error(f"{datetime.now()} Error al descifrar:", e)


    # Si es un mensaje de datos (no Join), puedes seguir desglosando FHDR, FPort, etc.
    def process_message(self, data, addr):
        """Procesa los mensajes recibidos"""
        logger.info(f"{datetime.now()} ✓ (Enter) Procesa los mensajes recibidos: \naddr {addr}\ndata: {data}\nlongitud: {len(data)} / {len(data.hex())} ")
        
        try:
            self.parse_lorawan_packet(data)    
            # Parsear el mensaje JSON
            #message = json.loads(data.decode('utf-8'))
            '''
            message = data.hex()
            
            json_data = ""
            if len(message) > 24:
                message = message[ 0 : 24]
                #message = message.hex()
                json_data = message[ 24 : len(message)]
                json_data = json_data.decode('utf-8')
                logger.info(f"{datetime.now()} (>24)  Mensaje recibido data: {data} longitud: {len(data)}\nmensaje : {message}\njson :{json_data} ")
            else:
                if len(message) == 24:
                    message = data.hex()
                    logger.info(f"{datetime.now()} (=24) Mensaje recibido data: {data} longitud: {len(data)}\nmensaje : {message}\njson :{json_data} ")
                else:
                    logger.info(f"{datetime.now()} (Unknow) Mensaje longitud desconocida: {len(data)}")                
            
            #message = json.loads(data)
            #logger.info(f"{datetime.now()} Mensaje recibido: {message}")

            # Verificar si es un mensaje del tipo UnconfirmedDataUp
            if message.get('rxpk'):
                for rx_packet in message['rxpk']:
                    if self.is_target_device(rx_packet):
                        logger.info(f"{datetime.now()} Dispositivo objetivo detectado, enviando downlink")
                        self.send_downlink(addr, rx_packet)
           '''             
        except json.JSONDecodeError:
            logger.error(f"{datetime.now()} ✗ Error decodificando JSON: {data}")
        except Exception as e:
            logger.error(f"{datetime.now()} ✗ Error procesando mensaje: {e}")
            
    def is_target_device(self, rx_packet):
        """Verifica si el paquete es del dispositivo objetivo"""
        try:
            # Extraer DevEUI del paquete (esto puede variar según el formato específico)
            dev_eui_rx = rx_packet.get('devEUI', '')
            if dev_eui_rx.lower() == DEV_EUI.lower():
                return True
            return False
        except Exception as e:
            logger.error(f"{datetime.now()} Error verificando dispositivo: {e}")
            return False
            
    def send_downlink(self, addr, rx_packet):
        """Envía un mensaje downlink al dispositivo"""
        logger.info(f"{datetime.now()} Envía un mensaje downlink al dispositivo addr {addr}")
        try:
            # Crear el mensaje downlink
            downlink_payload = "80029999010A81"
            
            # Construir el mensaje de respuesta
            response = {
                "txpk": {
                    "imme": True,
                    "freq": rx_packet.get('freq', 868.1),
                    "rfch": 0,
                    "powe": 14,
                    "modu": "LORA",
                    "datr": rx_packet.get('datr', 'SF7BW125'),
                    "codr": rx_packet.get('codr', '4/5'),
                    "ipol": True,
                    "size": len(bytes.fromhex(downlink_payload)),
                    "data": downlink_payload,
                    "brd": 0,
                    "ant": 0
                }
            }
            
            # Enviar el downlink
            response_json = json.dumps(response)
            self.sock.sendto(response_json.encode('utf-8'), addr)
            logger.info(f"{datetime.now()} Downlink enviado: {downlink_payload}")
            
        except Exception as e:
            logger.error(f"{datetime.now()} Error enviando downlink: {e}")

    def handle_join_request(self, message, addr):
        """Maneja las solicitudes de unión (Join Request)"""
        logger.info(f"{datetime.now()} Maneja las solicitudes de unión (Join Request) mensaje {message} addr {addr}")
        try:
            # Aquí iría la lógica para manejar el OTAA join
            # Este es un ejemplo básico
            logger.info(f"{datetime.now()} Solicitud de unión recibida")
            
            # En una implementación completa, aquí se verificarían los parámetros
            # y se enviaría una respuesta de unión aceptada
            
        except Exception as e:
            logger.error(f"{datetime.now()} Error en solicitud de unión: {e}")

def main():
    """Función principal"""
    logger.info(f"{datetime.now()} Iniciando servidor LoRaWAN")
    
    server = LoRaWANServer()
    try:
        server.start_server()
    except KeyboardInterrupt:
        logger.info(f"{datetime.now()} Servidor detenido por el usuario")
    except Exception as e:
        logger.error(f"{datetime.now()} Error fatal: {e}")

if __name__ == "__main__":
    main()

'''
✗ 
✓
🟢 
🔴
'''
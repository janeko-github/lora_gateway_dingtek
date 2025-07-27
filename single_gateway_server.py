import socket
import json
import struct
import time
import threading
import os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

GATEWAY_ID = "AA555A0000000000"
DEV_EUI = "8CF9572000133C5C"   
JOIN_EUI = "8CF9572000000000"  
APP_EUI = JOIN_EUI
APP_KEY = "2B7E151628AED2A6ABF7158809CF4F3C"

class SingleGatewayLoRaWANServer:
    def __init__(self, host='0.0.0.0', port=1700, gateway_config=None):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
        # Configuración del gateway específico
        self.gateway_config = gateway_config or {
            'eui': GATEWAY_ID,  # EUI del gateway esperado
            'ip': None,  # Se detecta automáticamente
            'port': None,  # Se detecta automáticamente
            'name': 'Gateway-1',
            'allowed_only': True  # Solo aceptar este gateway
        }
        
        # Estado del gateway
        self.gateway = {
            'connected': False,
            'last_seen': None,
            'addr': None,
            'pull_token': None,
            'stats': {},
            'uplink_count': 0,
            'downlink_count': 0
        }


        # Base de datos de dispositivos
        self.devices = {
            bytes.fromhex(DEV_EUI): {
                "appeui": bytes.fromhex(APP_EUI),
                "appkey": bytes.fromhex(APP_KEY),
                "last_devnonce": 0,
                "name": "Residuos 4281"
            }
        }
        
        self.active_sessions = {}
        
    def start(self):
        """Inicia el servidor"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        print(f"🚀 Servidor LoRaWAN iniciado en {self.host}:{self.port}")
        print(f"📡 Esperando gateway: {self.gateway_config['eui']} ({self.gateway_config['name']})")
        
        # Hilo para monitoreo del gateway
        threading.Thread(target=self.monitor_gateway, daemon=True).start()
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self.handle_packet(data, addr)
                
            except Exception as e:
                if self.running:
                    print(f"❌ Error recibiendo datos: {e}")
    
    def handle_packet(self, data, addr):
        """Maneja un paquete UDP del gateway"""
        try:
            packet = self.parse_semtech_packet(data)
            
            # Verificar si es el gateway esperado
            if packet.get('gateway_eui'):
                gateway_eui_hex = packet['gateway_eui'].hex().upper()
                
                if self.gateway_config['allowed_only']:
                    if gateway_eui_hex != self.gateway_config['eui'].upper():
                        print(f"⚠️  Gateway no autorizado: {gateway_eui_hex} desde {addr}")
                        return
            
            if packet['type'] == 0x00:  # PUSH_DATA
                self.handle_push_data(packet, addr)
                
            elif packet['type'] == 0x02:  # PULL_DATA
                self.handle_pull_data(packet, addr)
                
        except Exception as e:
            print(f"❌ Error procesando paquete de {addr}: {e}")
    
    def parse_semtech_packet(self, data):
        """Parsea un paquete UDP Semtech"""
        if len(data) < 4:
            raise ValueError("Paquete demasiado corto")
        
        version = data[0]
        token = struct.unpack('>H', data[1:3])[0]
        msg_type = data[3]
        
        result = {
            'version': version,
            'token': token,
            'type': msg_type,
            'payload': None
        }
        
        if msg_type in [0x00, 0x02]:  # PUSH_DATA o PULL_DATA
            if len(data) < 12:
                raise ValueError("Paquete demasiado corto para incluir Gateway EUI")
            gateway_eui = data[4:12]
            result['gateway_eui'] = gateway_eui
            
            if msg_type == 0x00 and len(data) > 12:  # PUSH_DATA con payload
                json_payload = data[12:].decode('utf-8')
                result['payload'] = json.loads(json_payload)
        
        return result
    
    def handle_push_data(self, packet, addr):
        """Maneja PUSH_DATA del gateway"""
        gateway_eui_hex = packet['gateway_eui'].hex().upper()
        
        # Enviar ACK
        ack = struct.pack('>BHB', 2, packet['token'], 0x01)  # PUSH_ACK
        self.socket.sendto(ack, addr)
        
        # Actualizar estado del gateway
        self.update_gateway_status(addr, packet)
        
        print(f"📡 PUSH_DATA de {self.gateway_config['name']} ({gateway_eui_hex})")
        
        # Procesar payload si existe
        if packet['payload']:
            if 'stat' in packet['payload']:
                self.process_gateway_stats(packet['payload']['stat'])
            
            if 'rxpk' in packet['payload']:
                for rxpk in packet['payload']['rxpk']:
                    self.process_uplink_message(rxpk)
    
    def handle_pull_data(self, packet, addr):
        """Maneja PULL_DATA del gateway"""
        gateway_eui_hex = packet['gateway_eui'].hex().upper()
        
        # Enviar ACK
        ack = struct.pack('>BHB', 2, packet['token'], 0x04)  # PULL_ACK
        self.socket.sendto(ack, addr)
        
        # Actualizar estado del gateway
        self.gateway.update({
            'connected': True,
            'last_seen': time.time(),
            'addr': addr,
            'pull_token': packet['token']
        })
        
        if not self.gateway_config.get('ip'):
            self.gateway_config['ip'] = addr[0]
            self.gateway_config['port'] = addr[1]
            print(f"✅ Gateway {self.gateway_config['name']} conectado desde {addr[0]}:{addr[1]}")
    
    def update_gateway_status(self, addr, packet):
        """Actualiza el estado del gateway"""
        self.gateway.update({
            'connected': True,
            'last_seen': time.time(),
            'addr': addr
        })
        
        if packet['payload'] and 'stat' in packet['payload']:
            self.gateway['stats'] = packet['payload']['stat']
    
    def process_gateway_stats(self, stats):
        """Procesa estadísticas del gateway"""
        print(f"📊 Estadísticas del gateway:")
        if 'rxnb' in stats:
            print(f"   Paquetes recibidos: {stats['rxnb']}")
        if 'rxok' in stats:
            print(f"   Paquetes válidos: {stats['rxok']}")
        if 'txnb' in stats:
            print(f"   Paquetes transmitidos: {stats['txnb']}")
        if 'temp' in stats:
            print(f"   Temperatura: {stats['temp']}°C")
    
    def process_uplink_message(self, rxpk):
        """Procesa un mensaje uplink"""
        try:
            import base64
            lorawan_data = base64.b64decode(rxpk['data'])
            
            self.gateway['uplink_count'] += 1
            
            print(f"\n📨 Uplink #{self.gateway['uplink_count']} recibido:")
            print(f"   Timestamp: {rxpk.get('tmst', 'N/A')}")
            print(f"   Frecuencia: {rxpk.get('freq', 'N/A')} MHz")
            print(f"   RSSI: {rxpk.get('rssi', 'N/A')} dBm")
            print(f"   SNR: {rxpk.get('lsnr', 'N/A')} dB")
            print(f"   Data Rate: {rxpk.get('datr', 'N/A')}")
            print(f"   Payload: {lorawan_data.hex().upper()}")
            
            # Procesar según tipo de mensaje
            mtype = (lorawan_data[0] >> 5) & 0x07
            
            if mtype == 0:  # Join Request
                self.handle_join_request(lorawan_data, rxpk)
            elif mtype in [2, 3, 4, 5]:  # Data messages
                self.handle_data_message(lorawan_data, rxpk)
            else:
                print(f"   Tipo de mensaje no soportado: {mtype}")
                
        except Exception as e:
            print(f"❌ Error procesando uplink: {e}")
    
    def handle_join_request(self, data, rxpk):
        """Maneja Join Request"""
        try:
            jr = self.parse_join_request(data)
            print(f"   📋 Join Request:")
            print(f"      AppEUI: {jr['appeui'].hex().upper()}")
            print(f"      DevEUI: {jr['deveui'].hex().upper()}")
            print(f"      DevNonce: {jr['devnonce']}")
            
            # Buscar dispositivo
            device = self.devices.get(jr['deveui'])
            if not device:
                print(f"      ❌ Dispositivo no registrado")
                return
            
            print(f"      📱 Dispositivo: {device['name']}")
            
            # Verificar integridad
            if not self.verify_join_request_mic(jr, device['appkey']):
                print(f"      ❌ MIC inválido")
                return
            
            # Verificar replay
            if jr['devnonce'] <= device['last_devnonce']:
                print(f"      ❌ DevNonce replay attack")
                return
            
            print(f"      ✅ Join Request válido")
            
            # Procesar join
            join_accept = self.process_join(jr, device, rxpk)
            if join_accept:
                self.send_join_accept(join_accept, rxpk)
                
        except Exception as e:
            print(f"      ❌ Error en Join Request: {e}")
    
    def parse_join_request(self, data):
        """Parsea Join Request"""
        if len(data) != 23:
            raise ValueError("Join Request inválido")
        
        return {
            'mhdr': data[0],
            'appeui': data[1:9][::-1],
            'deveui': data[9:17][::-1],
            'devnonce': struct.unpack('<H', data[17:19])[0],
            'mic': data[19:23]
        }
    
    def verify_join_request_mic(self, jr, appkey):
        """Verifica MIC del Join Request"""
        msg = bytearray()
        msg.append(jr['mhdr'])
        msg.extend(jr['appeui'][::-1])
        msg.extend(jr['deveui'][::-1])
        msg.extend(struct.pack('<H', jr['devnonce']))
        
        cipher = CMAC.new(appkey, ciphermod=AES)
        cipher.update(msg)
        calculated_mic = cipher.digest()[:4]
        
        return calculated_mic == jr['mic']
    
    def process_join(self, jr, device, rxpk):
        """Procesa el join y genera claves"""
        # Generar Join Accept
        appnonce = os.urandom(3)
        netid = bytes([0x00, 0x00, 0x01])
        devaddr = struct.unpack('<I', os.urandom(4))[0] & 0x01FFFFFF
        
        # Generar claves de sesión
        nwkskey, appskey = self.generate_session_keys(
            device['appkey'], appnonce, netid, jr['devnonce']
        )
        
        # Actualizar dispositivo
        device['last_devnonce'] = jr['devnonce']
        
        # Guardar sesión
        self.active_sessions[devaddr] = {
            'deveui': jr['deveui'],
            'device_name': device['name'],
            'nwkskey': nwkskey,
            'appskey': appskey,
            'fcnt_up': 0,
            'fcnt_down': 0,
            'joined_at': time.time()
        }
        
        print(f"      📝 Sesión creada:")
        print(f"         DevAddr: 0x{devaddr:08X}")
        print(f"         NwkSKey: {nwkskey.hex().upper()}")
        print(f"         AppSKey: {appskey.hex().upper()}")
        
        # Crear Join Accept encriptado
        ja_payload = self.create_join_accept(appnonce, netid, devaddr)
        encrypted_ja = self.encrypt_join_accept(ja_payload, device['appkey'])
        
        return {
            'payload': encrypted_ja,
            'devaddr': devaddr,
            'device_name': device['name']
        }
    
    def generate_session_keys(self, appkey, appnonce, netid, devnonce):
        """Genera NwkSKey y AppSKey"""
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
    
    def create_join_accept(self, appnonce, netid, devaddr):
        """Crea payload del Join Accept"""
        payload = bytearray()
        payload.extend(appnonce)
        payload.extend(netid)
        payload.extend(struct.pack('<I', devaddr))
        payload.append(0x00)  # DLSettings
        payload.append(0x01)  # RxDelay
        return payload
    
    def encrypt_join_accept(self, payload, appkey):
        """Encripta Join Accept"""
        mhdr = 0x20  # Join Accept
        
        # Calcular MIC
        mic_msg = bytearray([mhdr]) + payload
        cipher = CMAC.new(appkey, ciphermod=AES)
        cipher.update(mic_msg)
        mic = cipher.digest()[:4]
        
        # Agregar MIC
        full_payload = payload + mic
        
        # Encriptar
        cipher = AES.new(appkey, AES.MODE_ECB)
        while len(full_payload) % 16 != 0:
            full_payload.append(0)
        
        encrypted = bytearray()
        for i in range(0, len(full_payload), 16):
            block = cipher.encrypt(full_payload[i:i+16])
            encrypted.extend(block)
        
        return bytes([mhdr]) + encrypted
    
    def send_join_accept(self, join_accept, rxpk):
        """Envía Join Accept al gateway"""
        if not self.gateway['connected'] or not self.gateway['pull_token']:
            print(f"      ❌ Gateway no disponible para downlink")
            return
        
        try:
            import base64
            
            # Calcular timing para RX1 (1 segundo después)
            tmst_rx1 = rxpk['tmst'] + 1000000
            
            # Crear paquete de transmisión
            txpk = {
                "imme": False,
                "tmst": tmst_rx1,
                "freq": rxpk['freq'],
                "rfch": 0,
                "powe": 14,
                "modu": "LORA",
                "datr": rxpk['datr'],
                "codr": rxpk['codr'],
                "ipol": True,
                "size": len(join_accept['payload']),
                "data": base64.b64encode(join_accept['payload']).decode('ascii')
            }
            
            # Crear PULL_RESP
            pull_resp_payload = {"txpk": txpk}
            json_data = json.dumps(pull_resp_payload).encode('utf-8')
            header = struct.pack('>BHB', 2, self.gateway['pull_token'], 0x03)
            pull_resp = header + json_data
            
            # Enviar
            self.socket.sendto(pull_resp, self.gateway['addr'])
            self.gateway['downlink_count'] += 1
            
            print(f"      📤 Join Accept enviado (downlink #{self.gateway['downlink_count']})")
            print(f"         Dispositivo: {join_accept['device_name']}")
            print(f"         DevAddr: 0x{join_accept['devaddr']:08X}")
            
        except Exception as e:
            print(f"      ❌ Error enviando Join Accept: {e}")
    
    def handle_data_message(self, data, rxpk):
        """Maneja mensajes de datos"""
        print(f"   📦 Mensaje de datos (no implementado completamente)")
        # TODO: Implementar manejo de mensajes de datos
    
    def monitor_gateway(self):
        """Monitorea el estado del gateway"""
        while self.running:
            time.sleep(10)
            
            if self.gateway['connected']:
                if time.time() - self.gateway['last_seen'] > 60:
                    print(f"⚠️  Gateway {self.gateway_config['name']} desconectado")
                    self.gateway['connected'] = False
    
    def show_status(self):
        """Muestra estado del servidor"""
        print(f"\n📊 Estado del servidor:")
        print(f"   Gateway: {self.gateway_config['name']} ({self.gateway_config['eui']})")
        
        if self.gateway['connected']:
            last_seen = datetime.fromtimestamp(self.gateway['last_seen']).strftime('%H:%M:%S')
            print(f"   Estado: ✅ Conectado (último contacto: {last_seen})")
            print(f"   IP: {self.gateway_config.get('ip', 'N/A')}:{self.gateway_config.get('port', 'N/A')}")
            print(f"   Uplinks: {self.gateway['uplink_count']} | Downlinks: {self.gateway['downlink_count']}")
        else:
            print(f"   Estado: ❌ Desconectado")
        
        print(f"   Sesiones activas: {len(self.active_sessions)}")
        for devaddr, session in self.active_sessions.items():
            joined_time = datetime.fromtimestamp(session['joined_at']).strftime('%H:%M:%S')
            print(f"     0x{devaddr:08X}: {session['device_name']} (joined {joined_time})")
    
    def stop(self):
        """Detiene el servidor"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("🛑 Servidor detenido")
    def send_downlink_data(self, devaddr, fport, payload, confirmed=False):
        """
        Envía un mensaje de datos downlink a un dispositivo
        
        Args:
            devaddr: Dirección del dispositivo (int)
            fport: Puerto de aplicación (1-223)
            payload: Datos a enviar (bytes)
            confirmed: Si requiere confirmación del dispositivo
        """
        session = self.active_sessions.get(devaddr)
        if not session:
            print(f"❌ Sesión no encontrada para DevAddr 0x{devaddr:08X}")
            return False
        
        if not self.gateway['connected'] or not self.gateway['pull_token']:
            print(f"❌ Gateway no disponible para downlink")
            return False
        
        try:
            print(f"\n📤 Enviando configuración a {session['device_name']}:")
            print(f"   DevAddr: 0x{devaddr:08X}")
            print(f"   FPort: {fport}")
            print(f"   Payload: {payload.hex().upper()}")
            print(f"   Confirmado: {'Sí' if confirmed else 'No'}")
            
            # Crear mensaje LoRaWAN
            lorawan_msg = self.create_data_message(
                devaddr, session, fport, payload, confirmed
            )
            
            # Programar para envío inmediato
            txpk = {
                "imme": True,  # Envío inmediato
                "freq": 869.525,  # Frecuencia RX2 EU868
                "rfch": 0,
                "powe": 14,
                "modu": "LORA",
                "datr": "SF12BW125",  # Data rate RX2
                "codr": "4/5",
                "ipol": True,
                "size": len(lorawan_msg),
                "data": self.base64_encode(lorawan_msg)
            }
            
            # Enviar PULL_RESP
            pull_resp_payload = {"txpk": txpk}
            json_data = json.dumps(pull_resp_payload).encode('utf-8')
            header = struct.pack('>BHB', 2, self.gateway['pull_token'], 0x03)
            pull_resp = header + json_data
            
            self.socket.sendto(pull_resp, self.gateway['addr'])
            self.gateway['downlink_count'] += 1
            
            print(f"   ✅ Mensaje enviado (downlink #{self.gateway['downlink_count']})")
            return True
            
        except Exception as e:
            print(f"   ❌ Error enviando downlink: {e}")
            return False

# Configuración y uso
if __name__ == "__main__":
    # Configuración del gateway específico
    gateway_config = {
        'eui': 'AA555A0000000000',  # Cambiar por el EUI real de tu gateway
        'name': 'RAK7271-Gateway',   # Nombre descriptivo
        'allowed_only': False         # Solo aceptar este gateway
    }
    
    server = SingleGatewayLoRaWANServer(gateway_config=gateway_config)
    
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

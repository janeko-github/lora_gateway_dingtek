import socket
import json
import struct
import time
import threading
import os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

class SingleGatewayLoRaWANServer:
    def __init__(self, host='0.0.0.0', port=1700, gateway_config=None):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
        # Configuración del gateway específico
        self.gateway_config = gateway_config or {
            'eui': 'AA555A0000000000',  # EUI del gateway esperado
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
            bytes.fromhex("0123456789ABCDEF"): {
                "appeui": bytes.fromhex("FEDCBA9876543210"),
                "appkey": bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C"),
                "last_devnonce": 0,
                "name": "Sensor-001"
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
        """Maneja mensajes de datos uplink"""
        try:
            # Parsear mensaje de datos
            mhdr = data[0]
            mtype = (mhdr >> 5) & 0x07
            
            # Extraer DevAddr (4 bytes, little endian)
            devaddr = struct.unpack('<I', data[1:5])[0]
            
            # Buscar sesión
            session = self.active_sessions.get(devaddr)
            if not session:
                print(f"   ❌ Sesión no encontrada para DevAddr 0x{devaddr:08X}")
                return
            
            print(f"   📦 Mensaje de datos de {session['device_name']} (0x{devaddr:08X})")
            
            # Extraer FCtrl y FCnt
            fctrl = data[5]
            fcnt = struct.unpack('<H', data[6:8])[0]
            
            print(f"      FCnt: {fcnt}")
            print(f"      Tipo: {'Confirmed' if mtype in [4, 5] else 'Unconfirmed'}")
            
            # Verificar y actualizar contador
            if fcnt > session['fcnt_up']:
                session['fcnt_up'] = fcnt
            else:
                print(f"      ⚠️  FCnt replay: {fcnt} <= {session['fcnt_up']}")
                return
            
            # Decodificar payload si existe
            fport_start = 8
            if fctrl & 0x0F > 0:  # FOpts presente
                fopts_len = fctrl & 0x0F
                fport_start += fopts_len
            
            if len(data) > fport_start + 4:  # Hay FPort y payload
                fport = data[fport_start]
                encrypted_payload = data[fport_start + 1:-4]  # Sin MIC
                
                if encrypted_payload:
                    # Desencriptar payload
                    decrypted = self.decrypt_payload(
                        encrypted_payload, session['appskey'], 
                        devaddr, fcnt, is_uplink=True
                    )
                    
                    print(f"      FPort: {fport}")
                    print(f"      Payload: {decrypted.hex().upper()}")
                    print(f"      ASCII: {self.try_decode_ascii(decrypted)}")
            
            print(f"   ✅ Mensaje procesado correctamente")
            
        except Exception as e:
            print(f"   ❌ Error procesando mensaje de datos: {e}")
    
    def decrypt_payload(self, encrypted_data, key, devaddr, fcnt, is_uplink=True):
        """Desencripta payload de datos usando AES-CTR"""
        # Construir bloque A para AES-CTR
        a_block = bytearray(16)
        a_block[0] = 0x01  # Encryption flag
        a_block[1:5] = struct.pack('<I', devaddr)
        a_block[5] = 0x00 if is_uplink else 0x01  # Direction
        a_block[6:8] = struct.pack('<H', fcnt)
        # a_block[8] permanece 0 (FCnt upper bytes)
        # a_block[9:15] permanecen 0 (reserved)
        
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = bytearray()
        
        for i in range(0, len(encrypted_data), 16):
            # Incrementar contador
            a_block[15] = (i // 16) + 1
            
            # Encriptar bloque A
            s_block = cipher.encrypt(a_block)
            
            # XOR con datos
            chunk = encrypted_data[i:i+16]
            for j in range(len(chunk)):
                decrypted.append(chunk[j] ^ s_block[j])
        
        return bytes(decrypted)
    
    def try_decode_ascii(self, data):
        """Intenta decodificar datos como ASCII"""
        try:
            return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
        except:
            return "Non-ASCII"
    
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
    
    def create_data_message(self, devaddr, session, fport, payload, confirmed):
        """Crea un mensaje de datos LoRaWAN"""
        # MHDR
        mtype = 5 if confirmed else 3  # Confirmed/Unconfirmed Data Down
        mhdr = (mtype << 5) | 0x00  # Major version 0
        
        # MAC Header + DevAddr + FCtrl + FCnt
        msg = bytearray()
        msg.append(mhdr)
        msg.extend(struct.pack('<I', devaddr))
        
        # FCtrl (ADR=0, RFU=0, ACK=0, FPending=0, FOpts=0)
        fctrl = 0x00
        msg.append(fctrl)
        
        # FCnt (incrementar contador downlink)
        session['fcnt_down'] += 1
        msg.extend(struct.pack('<H', session['fcnt_down']))
        
        # FPort
        msg.append(fport)
        
        # Encriptar payload
        encrypted_payload = self.encrypt_payload(
            payload, session['appskey'], devaddr, 
            session['fcnt_down'], is_uplink=False
        )
        msg.extend(encrypted_payload)
        
        # Calcular MIC
        mic = self.calculate_data_mic(
            msg, session['nwkskey'], devaddr, 
            session['fcnt_down'], is_uplink=False
        )
        msg.extend(mic)
        
        return bytes(msg)
    
    def encrypt_payload(self, payload, key, devaddr, fcnt, is_uplink=True):
        """Encripta payload usando AES-CTR"""
        if not payload:
            return b''
        
        # Construir bloque A
        a_block = bytearray(16)
        a_block[0] = 0x01
        a_block[1:5] = struct.pack('<I', devaddr)
        a_block[5] = 0x00 if is_uplink else 0x01
        a_block[6:8] = struct.pack('<H', fcnt)
        
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = bytearray()
        
        for i in range(0, len(payload), 16):
            a_block[15] = (i // 16) + 1
            s_block = cipher.encrypt(a_block)
            
            chunk = payload[i:i+16]
            for j in range(len(chunk)):
                encrypted.append(chunk[j] ^ s_block[j])
        
        return bytes(encrypted)
    
    def calculate_data_mic(self, msg, nwkskey, devaddr, fcnt, is_uplink=True):
        """Calcula MIC para mensaje de datos"""
        # Construir bloque B0 para MIC
        b0 = bytearray(16)
        b0[0] = 0x49  # Flag
        b0[1:5] = struct.pack('<I', devaddr)
        b0[5] = 0x00 if is_uplink else 0x01
        b0[6:8] = struct.pack('<H', fcnt)
        b0[10] = len(msg)
        
        # Calcular CMAC
        cipher = CMAC.new(nwkskey, ciphermod=AES)
        cipher.update(b0 + msg)
        return cipher.digest()[:4]
    
    def base64_encode(self, data):
        """Codifica datos en base64"""
        import base64
        return base64.b64encode(data).decode('ascii')
    
    def send_config_command(self, devaddr, config_data):
        """
        Envía comando de configuración específico
        
        Args:
            devaddr: Dirección del dispositivo
            config_data: Diccionario con configuración
        """
        # Ejemplo de comandos de configuración
        if 'sampling_interval' in config_data:
            # Comando para cambiar intervalo de muestreo
            payload = bytearray([0x01])  # Comando ID
            payload.extend(struct.pack('<H', config_data['sampling_interval']))
            return self.send_downlink_data(devaddr, 10, payload, confirmed=True)
        
        elif 'power_level' in config_data:
            # Comando para cambiar nivel de potencia
            payload = bytearray([0x02])  # Comando ID  
            payload.append(config_data['power_level'])
            return self.send_downlink_data(devaddr, 10, payload, confirmed=True)
        
        elif 'reset' in config_data:
            # Comando de reset
            payload = bytearray([0xFF, 0x00])
            return self.send_downlink_data(devaddr, 10, payload, confirmed=True)
        
        elif 'custom_payload' in config_data:
            # Payload personalizado
            payload = config_data['custom_payload']
            fport = config_data.get('fport', 10)
            confirmed = config_data.get('confirmed', False)
            return self.send_downlink_data(devaddr, fport, payload, confirmed)
        
        else:
            print(f"❌ Comando de configuración no reconocido")
            return False

    def stop(self):
        """Detiene el servidor"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("🛑 Servidor detenido")

# Configuración y uso
if __name__ == "__main__":
    # Configuración del gateway específico
    gateway_config = {
        'eui': 'AA555A0000000000',  # Cambiar por el EUI real de tu gateway
        'name': 'RAK7371-Gateway',   # Nombre descriptivo
        'allowed_only': True         # Solo aceptar este gateway
    }
    
    server = SingleGatewayLoRaWANServer(gateway_config=gateway_config)
    
    def command_interface():
        """Interfaz de comandos para enviar configuraciones"""
        time.sleep(5)  # Esperar que inicie el servidor
        
        while server.running:
            try:
                print("\n" + "="*50)
                print("COMANDOS DISPONIBLES:")
                print("1. config <devaddr> sampling <seconds> - Cambiar intervalo")
                print("2. config <devaddr> power <level> - Cambiar potencia (0-15)")
                print("3. config <devaddr> reset - Resetear dispositivo")
                print("4. send <devaddr> <fport> <hex_payload> - Envío personalizado")
                print("5. status - Ver estado")
                print("6. quit - Salir")
                print("="*50)
                
                cmd = input("Comando: ").strip().split()
                if not cmd:
                    continue
                
                if cmd[0] == 'config' and len(cmd) >= 4:
                    devaddr = int(cmd[1], 16)
                    
                    if cmd[2] == 'sampling' and len(cmd) >= 4:
                        interval = int(cmd[3])
                        server.send_config_command(devaddr, {'sampling_interval': interval})
                        
                    elif cmd[2] == 'power' and len(cmd) >= 4:
                        power = int(cmd[3])
                        server.send_config_command(devaddr, {'power_level': power})
                        
                    elif cmd[2] == 'reset':
                        server.send_config_command(devaddr, {'reset': True})
                
                elif cmd[0] == 'send' and len(cmd) >= 4:
                    devaddr = int(cmd[1], 16)
                    fport = int(cmd[2])
                    payload = bytes.fromhex(cmd[3])
                    server.send_downlink_data(devaddr, fport, payload)
                
                elif cmd[0] == 'status':
                    server.show_status()
                
                elif cmd[0] == 'quit':
                    break
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ Error en comando: {e}")
    
    try:
        # Hilo para interfaz de comandos
        threading.Thread(target=command_interface, daemon=True).start()
        
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

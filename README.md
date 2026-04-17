# ARP Poisoning Tool

Este repositório contém uma ferramenta em Python para realizar ataques de ARP Poisoning (também conhecido como ARP Spoofing). A ferramenta foi desenvolvida para fins educacionais e de teste de segurança em ambientes controlados. **O uso indevido desta ferramenta é estritamente proibido e pode resultar em consequências legais.**

## O que é ARP Poisoning?

ARP Poisoning é uma técnica de ataque que explora vulnerabilidades no Address Resolution Protocol (ARP) para associar o endereço MAC do atacante ao endereço IP de outro host na rede, como o gateway ou uma vítima. Isso permite que o atacante intercepte, modifique ou desvie o tráfego de rede entre os hosts comprometidos.

## Funcionalidades

- **Envenenamento ARP:** Envia pacotes ARP falsificados para a vítima e o gateway, redirecionando o tráfego através da máquina do atacante.
- **Captura de Pacotes:** Opcionalmente, captura pacotes de rede da vítima para análise.
- **Restauração:** Restaura as tabelas ARP dos hosts afetados ao estado original após a interrupção do ataque.
- **Multiprocessamento:** Utiliza `multiprocessing` para executar o envenenamento e a captura de pacotes em threads separadas, garantindo maior estabilidade e controle.
- **Tratamento de Erros:** Inclui tratamento de erros para falhas na obtenção de MACs e interrupções do usuário (CTRL+C).

## Pré-requisitos

Para executar esta ferramenta, você precisará:

- Python 3.x
- Scapy (biblioteca de manipulação de pacotes de rede)

### Instalação de Dependências

```bash
pip install scapy
```

**Observação:** Em sistemas baseados em Linux, pode ser necessário executar com privilégios de root para a Scapy funcionar corretamente (`sudo python3 arper_improved.py ...`).

## Como Usar

1. Clone este repositório (ou baixe o arquivo `arper_improved.py`):

   ```bash
   git clone https://github.com/whitefoxcibersec/arp-poisoning-tool.git
   cd arp-poisoning-tool
   ```

2. Execute o script Python, fornecendo o IP da vítima, o IP do gateway e o nome da interface de rede:

   ```bash
   python3 arper_improved.py <IP_DA_VITIMA> <IP_DO_GATEWAY> <INTERFACE_DE_REDE>
   ```

   **Exemplo:**

   ```bash
   sudo python3 arper_improved.py 192.168.1.100 192.168.1.1 eth0
   ```

   - `<IP_DA_VITIMA>`: O endereço IP do alvo que você deseja envenenar.
   - `<IP_DO_GATEWAY>`: O endereço IP do gateway da rede (geralmente o roteador).
   - `<INTERFACE_DE_REDE>`: O nome da sua interface de rede (ex: `eth0`, `wlan0`, `enp0s3`).

3. Para interromper o ataque e restaurar as tabelas ARP, pressione `CTRL+C`.

## Estrutura do Código

O código é organizado em uma classe `Arper` e uma função auxiliar `get_mac`:

- `get_mac(targetip, interface)`:
    - Função responsável por descobrir o endereço MAC de um determinado IP na rede, utilizando pacotes ARP `who-has`.
    - Inclui tratamento de erros e um timeout para evitar bloqueios.

- `class Arper`:
    - `__init__(self, victim_ip, gateway_ip, interface)`:
        - Inicializa a classe com os IPs da vítima e do gateway, e a interface de rede.
        - Obtém os endereços MAC da vítima e do gateway usando `get_mac`.
        - Realiza verificações básicas para garantir que os MACs foram obtidos com sucesso.
        - Configura a Scapy para usar a interface especificada e desativa o modo verboso.

    - `poison(self)`:
        - Implementa a lógica principal do ataque de ARP Poisoning.
        - Constrói pacotes ARP de 
resposta (op=2) para a vítima e para o gateway.
        - Entra em um loop infinito, enviando continuamente os pacotes de envenenamento.
        - Inclui um `try-except` para capturar `KeyboardInterrupt` (CTRL+C) e chamar o método `restore()` antes de sair.

    - `restore(self)`:
        - Envia pacotes ARP legítimos para a vítima e o gateway, informando os MACs corretos um do outro.
        - Isso ajuda a restaurar as tabelas ARP ao estado normal, minimizando o impacto do ataque após sua interrupção.
        - Envia múltiplos pacotes (`count=7`) para aumentar a probabilidade de restauração bem-sucedida.

    - `sniff_packets(self, count=200)`:
        - Captura um número especificado de pacotes (`count`) que têm como origem ou destino o IP da vítima.
        - Utiliza um filtro BPF (`bpf_filter`) para otimizar a captura.
        - Salva os pacotes capturados em um arquivo `.pcap` (`arper.pcap`).
        - Inclui tratamento de erros e garante que o processo de envenenamento seja encerrado e as tabelas ARP restauradas, mesmo que a captura falhe.

    - `run(self)`:
        - Inicia dois processos separados usando `multiprocessing.Process`:
            - `poison_thread`: Executa o método `poison()` para realizar o envenenamento ARP.
            - `sniff_thread`: Executa o método `sniff_packets()` para capturar o tráfego.
        - Garante que ambos os processos sejam iniciados e aguarda a sua conclusão.

- `if __name__ == '__main__':`:
    - Bloco principal de execução do script.
    - Verifica se os argumentos de linha de comando necessários (IP da vítima, IP do gateway, interface) foram fornecidos.
    - Configura um `signal_handler` para o sinal `SIGINT` (CTRL+C), garantindo que a função `restore()` seja chamada e os processos sejam encerrados corretamente em caso de interrupção externa.
    - Instancia a classe `Arper` e chama o método `run()` para iniciar o ataque.

## Melhorias e Alterações em Relação ao Código Original

As seguintes melhorias foram implementadas no código original:

| Característica Original | Melhoria Implementada | Justificativa |
| :---------------------- | :-------------------- | :------------ |
| `get_mac` sem interface | `get_mac` com parâmetro `interface` | Garante que a requisição ARP seja enviada pela interface correta, essencial em sistemas com múltiplas interfaces. |
| `get_mac` sem tratamento de erro | `get_mac` com `try-except` e `verbose=False` | Torna a função mais robusta, tratando possíveis falhas na obtenção do MAC e evitando mensagens de erro desnecessárias da Scapy. |
| Variáveis de classe `victimmac`, `gatewaymac` | Variáveis de instância `victim_mac`, `gateway_mac` | Melhor clareza e aderência às convenções de Python para nomes de variáveis. |
| Mensagens de `print` informais | Mensagens de `print` padronizadas com `[INFO]`, `[ERRO]` | Melhora a legibilidade e facilita a depuração e o entendimento do fluxo do programa. |
| `poison` com `verbose=True` | `poison` com `verbose=False` | Reduz a verbosidade da Scapy durante o envio contínuo de pacotes, tornando a saída mais limpa. |
| `restore` com `count=1` | `restore` com `count=7` | Enviar múltiplos pacotes de restauração aumenta significativamente a chance de que as tabelas ARP sejam atualizadas corretamente em todos os hosts afetados. |
| `sniff` sem `timeout` | `sniff_packets` com `timeout=30` | Adiciona um tempo limite para a captura de pacotes, evitando que o processo de `sniff` fique bloqueado indefinidamente se não houver tráfego. |
| `sniff` sem tratamento de erro | `sniff_packets` com `try-except` e `finally` | Garante que a restauração seja chamada mesmo se a captura de pacotes falhar, e fornece feedback sobre erros. |
| `sniff` chamando `restore` e `terminate` do `poison_thread` | Lógica de encerramento e restauração centralizada | A lógica de encerramento do `poison_thread` e a chamada de `restore` foram movidas para o bloco `finally` de `sniff_packets` e para o `signal_handler`, garantindo um desligamento mais limpo e consistente. |
| Sem tratamento de `KeyboardInterrupt` global | Implementação de `signal_handler` para `SIGINT` | Permite que o programa responda a interrupções externas (CTRL+C) de forma graciosa, garantindo que a restauração ARP seja sempre tentada antes de sair. |
| Nomes de métodos e variáveis | Padronização para `snake_case` | Melhoria na legibilidade e conformidade com as convenções de estilo do Python (PEP 8). |
| Validação de argumentos de linha de comando | Adição de verificação `len(sys.argv)` | Garante que o usuário forneça todos os argumentos necessários, exibindo uma mensagem de uso em caso de erro. |

## Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests no repositório [whitefoxcibersec/arp-poisoning-tool](https://github.com/whitefoxcibersec/arp-poisoning-tool).

## Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## Aviso Legal

Esta ferramenta é fornecida 
APENAS para fins educacionais e de pesquisa em segurança de redes. O autor não se responsabiliza por qualquer uso indevido ou ilegal desta ferramenta. Utilize-a com responsabilidade e apenas em redes onde você tenha permissão explícita para realizar testes.

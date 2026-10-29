//  DECLARAÇÕES EXTERNAS (C puro dentro de código C++)

// Necessário porque wifi_conf.h é um header em C (API do SDK Realtek).
// Sem o extern "C" o linker não encontraria os símbolos (name mangling).

extern "C" {
  #include "wifi_conf.h"
}

#include <WiFi.h>

//  MACROS E CONSTANTES DE CONFIGURAÇÃO

#ifndef min
#define min(a,b) ((a)<(b)?(a):(b)) // fallback caso Arduino não defina
#endif


#define MAX_DISPOSITIVOS 50          // limite do vetor de dispositivos rastreados
#define TIMEOUT_DISPOSITIVO 2000     // 2 s sem ver o MAC => considera dispositivo inativo

#define MAX_REDES 50                 // máximo de redes alvo por comando SNIFF_ONLY
#define MAX_FRAMES_DEBUG 5           // quantos frames brutos guardar para debug
#define MAX_FRAME_DEBUG_LEN 24       // primeiros bytes guardados de cada frame

//  ESTRUTURAS DE DADOS

// Rede alvo (AP) que queremos monitorar
struct RedeAlvo {
  uint8_t bssid[6];  // MAC do Access Point
  uint8_t canal;     // canal Wi-Fi em que ele opera
};

// Dispositivo (estação/cliente) já visto
struct DispositivoVisto {
  uint8_t mac[6];              // MAC do cliente
  unsigned long ultimaVez;     // timestamp (millis) da última vez que foi visto
  bool ativo;                  // flag de ocupação do slot
};

// Cabeçalho MAC 802.11 (formato mínimo/geral).
// O frame_control é little-endian (bytes [0] e [1]).
// Endereços: addr1=Receiver, addr2=Transmitter, addr3=BSSID (na maioria dos casos).

typedef struct {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t addr1[6]; // Receiver
  uint8_t addr2[6]; // Transmitter
  uint8_t addr3[6]; // BSSID (na maioria dos casos)
  uint16_t seq_ctrl;
} ieee80211_hdr_t;

//  CONFIGURAÇÃO DE REDE (IP fixo do BW16, gateway = ESP8266 controlador)

IPAddress local_IP(192, 168, 4, 15);
IPAddress gateway(192, 168, 4, 99); // IP do ESP8266
IPAddress subnet(255, 255, 255, 0);

// BUFFERS DE DEBUG DE FRAMES BRUTOS (para inspeção manual no Serial)

uint8_t framesDebug[MAX_FRAMES_DEBUG][MAX_FRAME_DEBUG_LEN];
uint16_t framesDebugLen[MAX_FRAMES_DEBUG];
volatile int framesDebugCount = 0; // volatile pois é alterado dentro do callback

//  ENDPOINT DO SERVIDOR (ESP8266)

const char* espIP = "192.168.4.99";
const int espPort = 80;

//  CONTROLE DE POLLING DE COMANDOS

unsigned long lastPoll = 0;
const unsigned long pollInterval = 1000; // Consulta o servidor a cada 1 segundo

//  ESTADO GLOBAL DE SNIFFING

DispositivoVisto dispositivos[MAX_DISPOSITIVOS];
uint8_t bssidAlvo[6]; // MAC do AP que você quer monitorar
volatile unsigned long framesRecebidosTotal = 0; // contador total (volatile: alterado no callback)

//  FUNÇÕES AUXILIARES DE MAC

// Um MAC multicast/broadcast tem o bit menos significativo do 1º byte = 1
bool macMulticastOuBroadcast(const uint8_t* mac) {
  return (mac[0] & 0x01) != 0;
}

// Compara dois MACs (6 bytes)
bool macIgual(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 6) == 0;
}

// Verifica se é o MAC de broadcast FF:FF:FF:FF:FF:FF
bool macBroadcast(const uint8_t* mac) {
  uint8_t bc[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  return macIgual(mac, bc);
}

// Converte um MAC (uint8_t[6]) em String "AA:BB:CC:DD:EE:FF"
String macToString(const uint8_t* mac) {
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// Converte um caracter hex ('0'-'9','A'-'F','a'-'f') em nibble (0-15)
// Retorna 0xFF se inválido
uint8_t hexCharToByte(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return 0xFF;
}

// Faz parse de "AA:BB:CC:DD:EE:FF" em macOut[6]. Retorna false se inválido.
bool parseMac(String macStr, uint8_t* macOut) {
  macStr.trim();
  if (macStr.length() != 17) {
    Serial.println("parseMac: tamanho inválido");
    return false;
  }
  for (int i = 0; i < 6; i++) {
    int pos = i * 3;
    uint8_t hi = hexCharToByte(macStr[pos]);
    uint8_t lo = hexCharToByte(macStr[pos + 1]);
    if (hi == 0xFF || lo == 0xFF) {
      return false;
    }
    macOut[i] = (hi << 4) | lo;
    if (i < 5 && macStr[pos + 2] != ':') {
      return false;
    }
  }
  return true;
}

//  RASTREAMENTO DE DISPOSITIVOS

// Registra um MAC na tabela:
//  - se já existe e está ativo, apenas atualiza timestamp
//  - senão, ocupa o primeiro slot livre
// Ignora endereços de broadcast.

void registrarDispositivo(const uint8_t* mac) {
  if (macBroadcast(mac)) return;

  // 1) já conhecido? só atualiza
  for (int i = 0; i < MAX_DISPOSITIVOS; i++) {
    if (dispositivos[i].ativo && macIgual(dispositivos[i].mac, mac)) {
      dispositivos[i].ultimaVez = millis();
      //Serial.println("Atualizou dispositivo existente");
      return;
    }
  }
  // 2) novo: aloca slot vazio
  for (int i = 0; i < MAX_DISPOSITIVOS; i++) {
    if (!dispositivos[i].ativo) {
      memcpy(dispositivos[i].mac, mac, 6);
      dispositivos[i].ultimaVez = millis();
      dispositivos[i].ativo = true;
      //Serial.println("Novo dispositivo adicionado");
      return;
    }
  }
}

// Conta quantos dispositivos estão "ativos" (vistos dentro do TIMEOUT).
// Aproveita para invalidar (ativo=false) os que expiraram.
int contarDispositivosAtivos() {
  int count = 0;
  unsigned long agora = millis();
  for (int i = 0; i < MAX_DISPOSITIVOS; i++) {
    if (dispositivos[i].ativo) {
      if (agora - dispositivos[i].ultimaVez > TIMEOUT_DISPOSITIVO) {
        dispositivos[i].ativo = false; //expirou
      } else {
        count++;
      }
    }
  }
  return count;
}

// Devolve a lista de MACs ativos como string CSV ("AA:..,BB:..")
String obterListaDispositivosAtivos() {
  String lista = "";
  unsigned long agora = millis();
  for (int i = 0; i < MAX_DISPOSITIVOS; i++) {
    if (dispositivos[i].ativo && (agora - dispositivos[i].ultimaVez <= TIMEOUT_DISPOSITIVO)) {
      if (lista.length() > 0) lista += ",";
      lista += macToString(dispositivos[i].mac);
    }
  }
  return lista;
}

// Imprime no Serial Monitor os primeiros bytes dos frames capturados (debug)
void imprimirFramesDebug() {
  for (int i = 0; i < framesDebugCount; i++) {
    Serial.print("Frame " + String(i) + " len=" + String(framesDebugLen[i]) + " bytes: ");
    for (int j = 0; j < (framesDebugLen[i] < MAX_FRAME_DEBUG_LEN ? framesDebugLen[i] : MAX_FRAME_DEBUG_LEN); j++) {
      if (framesDebug[i][j] < 0x10) Serial.print("0");
      Serial.print(framesDebug[i][j], HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
}

//  CALLBACK DO MODO PROMÍSCUO (chamado para CADA frame 802.11 recebido)

// Cada frame: buf = bytes crus do frame 802.11, len = tamanho total
// Filtrar apenas frames de dados/gerência, verificar se o BSSID alvo
// aparece e extrair o MAC da estação (o endereço que NÃO é o BSSID)
void promiscCallback(unsigned char *buf, unsigned int len, void *userdata) {
  framesRecebidosTotal++;

  #ifdef DEBUG_RAW
    Serial.print("RAW: ");
    for (int i = 0; i < 24; i++) {
      if (buf[i] < 0x10) Serial.print("0");
      Serial.print(buf[i], HEX);
      Serial.print(" ");
    }
    Serial.println();
  #endif

  // Guarda até MAX_FRAMES_DEBUG frames brutos para debug
  if (framesDebugCount < MAX_FRAMES_DEBUG) {
    int copyLen = (len < MAX_FRAME_DEBUG_LEN) ? len : MAX_FRAME_DEBUG_LEN;
    memcpy(framesDebug[framesDebugCount], buf, copyLen);
    framesDebugLen[framesDebugCount] = len;
    framesDebugCount++;
  }

  // ---------- Detecta padding de 2 bytes no início do buffer ----------
  // Um Frame Control 802.11 "plausível" tem version=0, type 0..2, e
  // management frames NÃO podem ter bits ToDS/FromDS setados.
  auto plausivelFC = [](uint16_t fc) -> bool {
    uint8_t version = fc & 0x03;
    uint8_t type    = (fc >> 2) & 0x03;
    bool    toDS    = (fc >> 8) & 0x01;
    bool    fromDS  = (fc >> 9) & 0x01;
    if (version != 0) return false;
    if (type == 3)    return false;                    // type 3 é reservado
    if (type == 0 && (toDS || fromDS)) return false;   // mgmt sem DS bits
    return true;
  };

  // Verifica se o frame é curto demais para ter cabeçalho 802.11 completo
  if (len < sizeof(ieee80211_hdr_t)) return;

 uint16_t fc = buf[0] | (buf[1] << 8);
  if (!plausivelFC(fc)) {
    // Alguns firmwares entregam 2 bytes de padding antes do header real
    if (len < 2 + sizeof(ieee80211_hdr_t)) return;
    buf += 2;
    len -= 2;
    fc = buf[0] | (buf[1] << 8);
    if (!plausivelFC(fc)) return;
  }

  // ---------- Bits do Frame Control ----------
  uint8_t type    = (fc >> 2) & 0x03;
  uint8_t subtype = (fc >> 4) & 0x0F;
  bool    toDS    = (fc >> 8) & 0x01;
  bool    fromDS  = (fc >> 9) & 0x01;

   // ---------- Filtro por tipo/subtype ----------
  // Só frames que podem revelar clientes associados à rede
  bool aceitar = false;
  if (type == 2) {
    aceitar = true;                                   // Data: layout é o mesmo
  } else if (type == 0) {
    aceitar = (subtype == 0)  || (subtype == 1)  ||   // Assoc Req / Resp
              (subtype == 2)  || (subtype == 3)  ||   // Reassoc Req / Resp
              (subtype == 5)  ||                      // Probe Resp
              (subtype == 11);                        // Authentication
    // EXCLUÍDOS: Beacon (8) — só AP↔broadcast, não revela cliente
    //            ProbeReq (4) — dirigido a broadcast (BSSID nunca bate)
  }
  if (!aceitar) return;

  ieee80211_hdr_t *hdr = (ieee80211_hdr_t*)buf;

  // ---------- WDS: 4 endereços (ToDS=1 e FromDS=1) ----------
  bool fourAddr = toDS && fromDS;
  const uint8_t* addr4 = nullptr;
  if (fourAddr) {
    if (len < sizeof(ieee80211_hdr_t) + 6) return;    // precisa caber addr4
    addr4 = buf + sizeof(ieee80211_hdr_t);            // bytes [24..29]
  }

  // ---------- Busca o BSSID alvo em qualquer endereço ----------
  bool a1 = macIgual(hdr->addr1, bssidAlvo);
  bool a2 = macIgual(hdr->addr2, bssidAlvo);
  bool a3 = macIgual(hdr->addr3, bssidAlvo);
  bool a4 = fourAddr && macIgual(addr4, bssidAlvo);
  if (!a1 && !a2 && !a3 && !a4) return;

  // ---------- Identifica a estação pela direção do frame ----------
  //   ToDS=0, FromDS=1: AP→STA       → addr1 = cliente
  //   ToDS=1, FromDS=0: STA→AP       → addr2 = cliente
  //   ToDS=0, FromDS=0: IBSS/mgmt    → primeiro que não é o BSSID
  //   ToDS=1, FromDS=1: WDS          → addr4 = origem (nunca é cliente final)
  const uint8_t* macEstacao = nullptr;

  if (fourAddr) {
    if (!a4) macEstacao = addr4;
  } else if (fromDS && !toDS) {
    if (!a1) macEstacao = hdr->addr1;
  } else if (toDS && !fromDS) {
    if (!a2) macEstacao = hdr->addr2;
  } else {
    if (!a1)      macEstacao = hdr->addr1;
    else if (!a2) macEstacao = hdr->addr2;
    else if (!a3) macEstacao = hdr->addr3;
  }

  // Debug: mostra sempre o addr3 (normalmente BSSID)
  /*Serial.print("BSSID no frame: ");
    for (int i = 0; i < 6; i++) {
      Serial.print(hdr->addr3[i], HEX);
      Serial.print(":");
    }
    Serial.println();
  */
  // Se o BSSID alvo não aparece em nenhum endereço, ignora
  if (macEstacao == nullptr) return;
  if (macMulticastOuBroadcast(macEstacao)) return;

  // Sanidade extra: MAC totalmente zero nunca é uma estação válida
  static const uint8_t zeros[6] = {0,0,0,0,0,0};
  if (macIgual(macEstacao, zeros)) return;

  registrarDispositivo(macEstacao);
}

//  CONTROLE DO SNIFFING

// Liga o modo promíscuo no canal informado, fixando o BSSID alvo.
// IMPORTANTE: desconecta do Wi-Fi, pois modo promíscuo conflita com STA mode.
void iniciarSniffing(const uint8_t* bssid, uint8_t canal) {
  memcpy(bssidAlvo, bssid, 6);
  memset(dispositivos, 0, sizeof(dispositivos));

  WiFi.disconnect();
  delay(500);

  wifi_set_channel(canal); // sintoniza no canal do AP

  // RTW_PROMISC_ENABLE_2 = modo promíscuo do SDK Realtek (Ameba)
  int retPromisc = wifi_set_promisc(RTW_PROMISC_ENABLE_2, promiscCallback, 1);
  Serial.print("wifi_set_promisc retornou: ");
  Serial.println(retPromisc);

}

// Desliga modo promíscuo e restabelece conexão com o AP controlador
void pararSniffing() {
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0);

  // Reconecta ao Wi-Fi
  WiFi.disconnect();
  delay(200);
  WiFi.config(local_IP, gateway, subnet);
  conectarWiFi();
}

//  CONEXÃO Wi-Fi (retry infinito até conectar)

void conectarWiFi() {
  const unsigned long timeoutPorTentativa = 2000;
  int tentativa = 0;

  while (WiFi.status() != WL_CONNECTED) {
    tentativa++;
    Serial.print("Tentativa ");
    Serial.print(tentativa);
    Serial.println(" de conexão...");

    WiFi.disconnect();
    delay(500);
    WiFi.begin("Deauther", "12345678"); // credenciais fixas do ESP

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutPorTentativa) {
      delay(300);
      Serial.print(".");
    }

    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("\nFalhou, tentando novamente...");
      delay(1000);
    }
  }

  Serial.println("\nBW16 Conectado ao AP do ESP8266!");
  Serial.println(WiFi.localIP());
}

//  HTTP CLIENT (GET e POST via WiFiClient)

// Faz GET simples e devolve o corpo (sem cabeçalhos) como String
String httpGet(String url) {
  WiFiClient client;
  client.setTimeout(500);
  String response = "";

  if (client.connect(espIP, espPort)){
    client.println("GET " + url + " HTTP/1.1");
    client.println("Host: 192.168.4.99");
    client.println("Connection: close");
    client.println();
    unsigned long timeout = millis() + 1000;
    bool headerEnded = false;
    while ((client.connected() || client.available()) && millis() < timeout) {
      if (client.available()) {
        String line = client.readStringUntil('\n');
        line.trim();
        if (!headerEnded) {
          if (line.length() == 0) {
            headerEnded = true;
          }
          // ignora cabeçalhos
        } else {
          response += line;
        }
      }
    }
    client.stop();
  }
  response.trim();
  return response;
}

// Consulta o servidor para saber se o operador pediu parada (cancelamento)
bool verificarParada() {
  if (WiFi.status() != WL_CONNECTED) return false;
  Serial.println("[D] verificarParada: enviando GET");
  unsigned long t0 = millis();
  String response = httpGet("/api/status-parada");
  Serial.println("[D] verificarParada: resp='" + response + "' em " + String(millis() - t0) + "ms");
  return (response.indexOf("true") >= 0);
}

// Polling de comandos (chamado a cada 1 s no loop)
void verificarComandos() {
  String response = httpGet("/api/obter-comando");
  if (response.length() > 0 && response != "NONE" && response != "Nao encontrado") {
    Serial.println("Comando Recebido: " + response);
    processarComando(response);
  }
}

// Envia resultado via POST JSON para a rota indicada, com até 5 tentativas
void enviarResultado(String jsonPayload, String rota) {
  for (int tentativa = 1; tentativa <= 5; tentativa++) {
    WiFiClient client;
    client.setTimeout(1000);
    if (client.connect(espIP, espPort)) {
      client.println("POST " + rota + " HTTP/1.1");
      client.println("Host: 192.168.4.99");
      client.println("Content-Type: application/json");
      client.print("Content-Length: ");
      client.println(jsonPayload.length());
      client.println("Connection: close");
      client.println();
      client.println(jsonPayload);
      client.stop();
      Serial.println("Resultado enviado para " + rota + " (tentativa " + String(tentativa) + ")");
      return;
    } else {
      Serial.print("Falha na tentativa ");
      Serial.println(tentativa);
      delay(1000);
    }
  }
  Serial.println("Falha ao enviar resultado após 5 tentativas");
}

//  PARSER DE LISTAS DE REDES

// Formato esperado: "AA:BB:CC:DD:EE:FF,6;AA:BB:...,11;..."
// Retorna quantas redes foram parseadas com sucesso.
int parseListaRedes(String payload, RedeAlvo* redes, int maxRedes) {
  int count = 0;
  int start = 0;
  while (count < maxRedes) {
    int fimEntrada = payload.indexOf(';', start);
    String entrada = (fimEntrada == -1) ? payload.substring(start) : payload.substring(start, fimEntrada);
    entrada.trim();
    if (entrada.length() > 0) {
      int virgula = entrada.indexOf(',');
      if (virgula != -1) {
        String bssidStr = entrada.substring(0, virgula);
        String canalStr = entrada.substring(virgula + 1);
        if (parseMac(bssidStr, redes[count].bssid)) {
          redes[count].canal = (uint8_t)canalStr.toInt();
          count++;
        }
      }
    }
    if (fimEntrada == -1) break;
    start = fimEntrada + 1;
  }
  return count;
}


//  LÓGICA DE TESTE DE "VULNERABILIDADE"

// Executa 2 janelas de sniffing na mesma rede:
//   - 1ª janela: descobre os MACs presentes no "início"
//   - intervalo (sem sniff)
//   - 2ª janela: descobre os MACs "durante"
// Envia cada resultado ao servidor (para que ele calcule, p.ex., rotação
// de MAC / evasão / mudança de clientes).

void executarTesteVulnerabilidade(String bssidStr, uint8_t canal, int tempo1, int tempo2, int intervalo) {
  uint8_t bssid[6];
  if (!parseMac(bssidStr, bssid)) return;

  Serial.println("Iniciando teste de vulnerabilidade para " + bssidStr);

  // 1º sniffing
  int dispositivosInicial = executarSniffing(bssid, canal, tempo1);

  String listaInicial = obterListaDispositivosAtivos();
  Serial.println("Lista inicial de MACs: " + listaInicial);
  delay(600); 
  pararSniffing();
  if (WiFi.status() != WL_CONNECTED) conectarWiFi();
  delay(300);    

  // Envia resultado do 1º sniffing
  String jsonInicial = "{\"bssid\":\"" + bssidStr +
                        "\",\"canal\":" + String(canal) +
                        ",\"dispositivos\":" + String(dispositivosInicial) +
                        ",\"macs\":\"" + listaInicial + "\"}";
  enviarResultado(jsonInicial, "/api/resultado-sniff-inicial");

  // Intervalo (sem sniff) - checa cancelamento a cada 100 ms
  unsigned long inicioIntervalo = millis();
  while (millis() - inicioIntervalo < intervalo) {
    delay(100);
    if (verificarParada()) {
      Serial.println("Parada solicitada durante o intervalo.");
      pararSniffing();
      return;  // encerra o teste imediatamente
    }
  }

  // 2º sniffing
  int dispositivosDurante = executarSniffing(bssid, canal, tempo2);
  String listaDurante = obterListaDispositivosAtivos();
  Serial.println("Lista durante de MACs: " + listaDurante);
  pararSniffing();

  // Envia resultado do 2º sniffing
  String jsonDurante = "{\"bssid\":\"" + bssidStr +
                        "\",\"dispositivos\":" + String(dispositivosDurante) +
                        ",\"macs\":\"" + listaDurante + "\"}";
  enviarResultado(jsonDurante, "/api/resultado-sniff-durante");
}

// Executa UM período de sniffing e devolve a contagem de dispositivos ativos.
// Também respeita pedido de parada (checado a cada 100 ms).

int executarSniffing(uint8_t* bssid, uint8_t canal, unsigned long duracaoMs) {
  iniciarSniffing(bssid, canal);
  unsigned long inicio = millis();

  while (millis() - inicio < duracaoMs) {
    delay(100);
    yield();
}
  int total = contarDispositivosAtivos();
  Serial.println("Total de frames brutos recebidos: " + String(framesRecebidosTotal));
  Serial.println("Frames capturados (debug):");
  imprimirFramesDebug();  
  framesRecebidosTotal = 0; // reseta para próxima contagem 
  framesDebugCount = 0; 
  return total;
}

//  PARSER / DISPATCHER DE COMANDOS

// Comandos suportados (enviados pelo ESP8266 via HTTP):
//   VULN_TEST|<bssid>,<canal>,<t1>,<t2>,<intervalo>
//       OU  VULN_TEST|<lista com ; entre redes>
//   SNIFF_ONLY|<segundos>|<lista de "bssid,canal;...">
//   SNIFF_LIST|<lista de "bssid,canal;...">

void processarComando(String cmd) {

  // Comando de teste de vulnerabilidade (lista ou rede única)
  if (cmd.startsWith("VULN_TEST")) {
  int p1 = cmd.indexOf('|');
  if (p1 == -1) {
    Serial.println("Comando VULN_TEST mal formatado");
    return;
  }
  String listaStr = cmd.substring(p1 + 1);

  // Verifica se é uma lista (contém ';')
  if (listaStr.indexOf(';') != -1) {
    int start = 0;
    while (start < listaStr.length()) {
      int fim = listaStr.indexOf(';', start);
      String entrada;
      if (fim == -1) {
        entrada = listaStr.substring(start);
        start = listaStr.length();
      } else {
        entrada = listaStr.substring(start, fim);
        start = fim + 1;
      }
      entrada.trim();
      if (entrada.length() == 0) continue; 

      // Cada entrada deve ter 5 campos: bssid,canal,tempo1,tempo2,intervalo
      int c1 = entrada.indexOf(',');
      int c2 = entrada.indexOf(',', c1 + 1);
      int c3 = entrada.indexOf(',', c2 + 1);
      int c4 = entrada.indexOf(',', c3 + 1);

      if (c1 == -1 || c2 == -1 || c3 == -1 || c4 == -1) {
        Serial.println("Entrada mal formatada: " + entrada);
        continue;
      }

      String bssid = entrada.substring(0, c1);
      uint8_t canal = entrada.substring(c1 + 1, c2).toInt();
      int tempo1 = entrada.substring(c2 + 1, c3).toInt() * 1000;   // ms
      int tempo2 = entrada.substring(c3 + 1, c4).toInt() * 1000;
      int intervalo = entrada.substring(c4 + 1).toInt() * 1000;

      Serial.println("Testando rede: " + bssid);
      executarTesteVulnerabilidade(bssid, canal, tempo1, tempo2, intervalo);
      delay(1000);  // pequena pausa entre redes
    }
    Serial.println("Todos os testes concluídos.");
  } else {
    // Rede única
    int c1 = listaStr.indexOf(',');
    int c2 = listaStr.indexOf(',', c1 + 1);
    int c3 = listaStr.indexOf(',', c2 + 1);
    int c4 = listaStr.indexOf(',', c3 + 1);

    if (c1 == -1 || c2 == -1 || c3 == -1 || c4 == -1) {
      Serial.println("Comando VULN_TEST (rede única) mal formatado");
      return;
    }

    String bssid = listaStr.substring(0, c1);
    uint8_t canal = listaStr.substring(c1 + 1, c2).toInt();
    int tempo1 = listaStr.substring(c2 + 1, c3).toInt() * 1000;
    int tempo2 = listaStr.substring(c3 + 1, c4).toInt() * 1000;
    int intervalo = listaStr.substring(c4 + 1).toInt() * 1000;

    executarTesteVulnerabilidade(bssid, canal, tempo1, tempo2, intervalo);
  }
}
  // SNIFF ONLY
  // Formato: SNIFF_ONLY|<segundos>|<lista "bssid,canal;...">
  // Sniffa cada rede pelo tempo fixo e reporta devices em /api/relatorio-sniff
  else if (cmd.startsWith("SNIFF_ONLY")) {
  int p1 = cmd.indexOf('|');
  int p2 = cmd.indexOf('|', p1 + 1);
  if (p1 == -1 || p2 == -1) { Serial.println("Comando SNIFF_ONLY mal formatado"); return; }

  int tempo = cmd.substring(p1 + 1, p2).toInt() * 1000;
  String listaStr = cmd.substring(p2 + 1);

  RedeAlvo redes[MAX_REDES];
  int totalRedes = parseListaRedes(listaStr, redes, MAX_REDES);

  for (int i = 0; i < totalRedes; i++) {
    String bssidStr = macToString(redes[i].bssid);
    Serial.println("Sniffing rede " + String(i+1) + "/" + String(totalRedes) + ": " + bssidStr);

    int dispositivos = executarSniffing(redes[i].bssid, redes[i].canal, tempo);
    Serial.println("Preparando para enviar resultado...");

    // Precisa reconectar o Wi-Fi antes de postar (promíscuo derrubou a STA)
    pararSniffing();      // desliga promíscuo, desconecta, reconecta ao AP
    delay(500);           // dá tempo à pilha TCP/IP subir

    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("WiFi não reconectou, tentando novamente...");
      conectarWiFi();
      delay(500);
    }

    String json = "{\"bssid\":\"" + bssidStr + "\",\"devices\":" + String(dispositivos) + "}";
    Serial.println(json);
    enviarResultado(json, "/api/relatorio-sniff");

    delay(300);
  }
  Serial.println("Sniffing concluído.");
}

  // SNIFF LIST
  // Variante simples: sniff fixo de 5 s por rede, sem parâmetro de tempo
  else if (cmd.startsWith("SNIFF_LIST")) {
    // Código original para apenas contar dispositivos (mantido se necessário)
    int p1 = cmd.indexOf('|');
    if (p1 == -1) return;
    String listaStr = cmd.substring(p1 + 1);
    RedeAlvo redes[MAX_REDES];
    int totalRedes = parseListaRedes(listaStr, redes, MAX_REDES);


    for (int i = 0; i < totalRedes; i++) {
      if (verificarParada()) {
        Serial.println("Parada solicitada entre redes.");
        break;
      }

      String bssidStr = macToString(redes[i].bssid);
      int dispositivos = executarSniffing(redes[i].bssid, redes[i].canal, 5000);
      enviarResultado("{\"bssid\":\"" + bssidStr + "\",\"devices\":" + String(dispositivos) + "}", "/api/relatorio-sniff");
    }
  }
}

void setup() {
  Serial.begin(115200);
  WiFi.config(local_IP, gateway, subnet); // IP fixo
  conectarWiFi();                         // Conecta ao ESP
}

void loop() {
  // Se caiu, reconecta
  if (WiFi.status() != WL_CONNECTED) {
    conectarWiFi();
  }

  // Polling periódico por novos comandos (1 Hz)
  if (millis() - lastPoll >= pollInterval) {
    lastPoll = millis();
    verificarComandos();
  }
}
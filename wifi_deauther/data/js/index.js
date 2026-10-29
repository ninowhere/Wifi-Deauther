import { evtSource, iniciarMonitoramentoStatus, showToast, verificarStatusBW16, sincronizarHorario, SwalDark } from './common.js';

iniciarMonitoramentoStatus();
let arrayRedes = [];

const KEY = 'deauther_logs_prompt_v1';
const FETCH_TIMEOUT_MS = 3000;

// Garante o fechamento imediato do socket TCP no ESP8266 ao fechar/mudar de aba
window.addEventListener("beforeunload", function() {
    if (evtSource) {
        evtSource.close();
    }
});

// Resincroniza também quando a aba volta ao foco
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) sincronizarHorario();
});

// Função para buscar logs antigos
async function buscarInfoLogs() {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
        const r = await fetch('/api/logs/info', { signal: ctrl.signal, cache: 'no-store' });
        if (!r.ok) return null;
        return await r.json();          // { exists, bytes }
    } catch {
        return null;                    // ESP offline, timeout, etc. → silêncio
    } finally {
        clearTimeout(timer);
    }
}

async function apagarLogs() {
    try {
        const r = await fetch('/api/logs/clear', { method: 'POST' });
        return r.ok;
    } catch {
        return false;
    }
}

export async function checarLogsAntigos() {
    // Já perguntou antes? Sai.
    if (localStorage.getItem(KEY)) return;

    const info = await buscarInfoLogs();

    // Sem resposta (ESP offline/timeout) → não marca nada, tenta de novo depois
    if (!info) return;

    // Sem log antigo → não marca nada, tenta de novo na próxima visita
    if (!info.exists || info.bytes === 0) return;

    const kb = (info.bytes / 1024).toFixed(1);

    const { isConfirmed } = await SwalDark.fire({
        icon: 'question',
        title: 'Logs antigos encontrados',
        html: `O ESP tem <b>${kb} KB</b> de logs de sessões anteriores.<br>Deseja apagar?`,
        showCancelButton: true,
        confirmButtonText: 'Apagar',
        cancelButtonText: 'Manter',
        reverseButtons: true,
        focusCancel: true,        // default seguro = manter
        allowOutsideClick: false,
    });

    if (isConfirmed) {
        const ok = await apagarLogs();
        if (ok) {
            localStorage.setItem(KEY, 'apagado');
            SwalDark.fire({
                icon: 'success', title: 'Logs apagados',
                timer: 1500, showConfirmButton: false,
            });
        } else {
            // Não marca → na próxima abre de novo (foi falha, não escolha)
            SwalDark.fire({
                icon: 'error', title: 'Falha ao apagar',
                text: 'Tente novamente pela página de logs.',
            });
        }
    } else {
        localStorage.setItem(KEY, 'mantido');
        SwalDark.fire({
            icon: 'info', title: 'Logs mantidos',
            timer: 1200, showConfirmButton: false,
        });
    }
}

// Helper: chame depois de /api/logs/clear pra permitir perguntar de novo no futuro
export function resetarPromptLogs() {
    localStorage.removeItem(KEY);
}

var ordemCrescente = true;
document.getElementById("sinal").addEventListener("click", function () {
    ordemCrescente = !ordemCrescente; // Inverte o estado
    ordena();
});

function ordena() {
    if (ordemCrescente) {
        arrayRedes.sort((a, b) => a.rssi - b.rssi);
    } else {
        arrayRedes.sort((a, b) => b.rssi - a.rssi);
    }

    renderizarTabelaCompleta();
}

evtSource.addEventListener("scan", (e) =>{
    try {
        const data = JSON.parse(e.data);

        if (data.TYPE === "SCAN") {
            // 1. Procura o índice da rede no array
            const index = arrayRedes.findIndex(rede => rede.bssid === data.bssid);

            if (index !== -1) {
                // Se index não for -1, a rede já existe no array
                // Rede dentro do array é atualizada
                arrayRedes[index] = data;
                //console.log("Rede atualizada no array:", data.ssid);
            } else {
                // Se for -1, ela não existe
                arrayRedes.push(data);
                //console.log("Nova rede adicionada ao array:", data.ssid);
            }
    
            localStorage.setItem("redes_salvas", JSON.stringify(arrayRedes));
            ordena();

            /*console.log("Estado atual do Array de Redes:");
            arrayRedes.forEach((rede, index) => {
                console.log(`Posição ${index}: SSID: ${rede.ssid} | BSSID: ${rede.bssid}`);
            });*/

            renderizarTabelaCompleta();
        }
    }
    catch (err) {
        console.error("Erro ao processar JSON:", err);
    }
});

document.addEventListener("DOMContentLoaded", () => {
    const redesSalvas = localStorage.getItem("redes_salvas");

    if (redesSalvas) {
        arrayRedes = JSON.parse(redesSalvas);
        renderizarTabelaCompleta(); // Renderiza as redes armazenadas imediatamente
    }
    checarLogsAntigos();
});

const selectAllSwitch = document.getElementById('select-all-switch');
selectAllSwitch.addEventListener('change', function () {
    const checkboxes = document.querySelectorAll('.network-checkbox');
    checkboxes.forEach(checkbox => {
        checkbox.checked = selectAllSwitch.checked;
    });
});

document.querySelectorAll('.network-checkbox').forEach(checkbox => {
    checkbox.addEventListener('change', atualizarEstadoSwitchSelecionarTodas);
});

function atualizarEstadoSwitchSelecionarTodas() {
    const checkboxes = document.querySelectorAll('.network-checkbox');
    const todosMarcados = Array.from(checkboxes).every(checkbox => checkbox.checked);
    selectAllSwitch.checked = todosMarcados;
}

function renderizarTabelaCompleta() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = ""; // Limpa a tabela

    arrayRedes.forEach(data => {
        const row = tbody.insertRow();
        const rowId = "net-" + data.bssid.replace(/:/g, '-');
        row.id = rowId;

        // Só 'Aberta' é realmente sem senha.
        // 'Auto' = WPA/WPA2 automático → TEM senha.
        // 'Desconhecido' → tratamos como protegida por segurança.
        const isOpen = (data.enc === 'Aberta');
        const emoji  = isOpen ? '🔓' : '🔐';

        row.innerHTML = `
                    <td class="box"><input type="checkbox" class="network-checkbox" value="${data.bssid}"></td>
                    <td>${data.bssid}</td>
                    <td>${data.ssid}</td>
                    <td>${data.chan}</td>
                    <td>${data.rssi} dBm</td>
                     <td><span class="${isOpen ? '' : 'status-online'}">${emoji} ${data.enc}</span></td>
                `;
    });
    atualizarEstadoSwitchSelecionarTodas();
}

async function enviarAlvos(comando, destino) {

    // 1. Coleta checkboxes marcados
    const checkboxes = document.querySelectorAll(".network-checkbox");
    const bssidsSelecionados = [];
    checkboxes.forEach(box => {
        if (box.checked && box.value !== "") bssidsSelecionados.push(box.value);
    });

    if (bssidsSelecionados.length === 0) {
        showToast("Por favor, selecione ao menos uma rede da lista.");
        return false;
    }

    // 2. Filtra os objetos completos e salva no localStorage
    const objetosSelecionados = arrayRedes.filter(rede =>
        bssidsSelecionados.includes(rede.bssid)
    );
    localStorage.setItem("redes_selecionadas", JSON.stringify(objetosSelecionados));

    // 3. Monta o payload
    const alvosComCanal = objetosSelecionados.map(rede => ({
        bssid: rede.bssid,
        chan: rede.chan
    }));

    const payload = { comando: comando, alvos: alvosComCanal };

    // 4. Envia
    try {
        const response = await fetch("/configurar-alvos", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            showToast("Erro no servidor ao processar a configuração.", true);
            return false;
        }

        if (destino) window.location.href = destino;
        return true;

    } catch (error) {
        console.error("Erro na requisição Fetch:", error);
        showToast("Falha na comunicação com o ESP8266.", true);
        return false;
    }
}

// Botão para enviar redes selecionadas
document.getElementById("btn-enviar").addEventListener("click", async () => {

    // 1. Pergunta ao ESP se o BW16 está online (usa o mesmo /status-bw16)
    const bw16Online = await verificarStatusBW16();

    // 2. Se o BW16 está online → fluxo de vulnerabilidade (usa BW16)
    if (bw16Online) {
        await enviarAlvos("vuln", "attack.html");
        return;
    }

    // 3. BW16 offline -> confirma se o usuário quer ataque local
    const { isConfirmed } = await SwalDark.fire({
        icon: 'warning',
        title: '⚠️  BW16 OFFLINE  ⚠️',
        html: `O BW16 não está respondendo, então o teste de vulnerabilidade com sniffing NÃO pode ser executado.<br><br>
       Deseja usar o <b>ATAQUE LOCAL</b> pelo próprio ESP8266?<br>
       <small>(Isso desconecta os clientes das redes selecionadas, mas não faz medição antes/depois.)</small>`,
        showCancelButton: true,
        confirmButtonText: 'Continuar',
        cancelButtonText: 'Voltar',
        reverseButtons: true,
        focusCancel: true,        // default seguro = manter
        allowOutsideClick: false,
    });

    // 4. Executa o ataque local (sem BW16)
    if (isConfirmed) {
        enviarAlvos("atacar", "attack.html");
    }
});

// Botão para enviar redes selecionadas para sniff
document.getElementById("btn-sniff").addEventListener("click", async () => {

    const bw16Online = await verificarStatusBW16();

    if (!bw16Online) {
        const prosseguir = confirm(
            "AVISO: O BW16 não está conectado à rede Wi-Fi!\n\n" +
            "O sniffing depende do BW16. Deseja prosseguir mesmo assim?"
        );
        if (!prosseguir) return;   // cancela tudo
    }

    await enviarAlvos("sniff", "attack.html");
});
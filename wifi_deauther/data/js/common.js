// Elementos do DOM (podem existir ou não em todas as páginas)
const statusContainer = document.getElementById('connection-status');
const statusText = document.getElementById('status-text');
const bw16Container = document.getElementById('bw16-status');
const bw16Text = document.getElementById('bw16-status-text');

import Swal from '../lib/sweetalert2.esm.all.js'; 

// --- Sweet Alert ---
// Exporta um modelo pronto padrão
export const SwalDark = Swal.mixin({
  background: '#222',
  color: '#eee',
  confirmButtonColor: '#7CD650',
  cancelButtonColor: '#DE3545'
});

// --- Sincronização de horário ---

export function horaAgora() {
    const n = new Date();
    const p = v => String(v).padStart(2, "0");
    return `[${p(n.getHours())}:${p(n.getMinutes())}:${p(n.getSeconds())}]`;
}

export function sincronizarHorario() {
    const now = new Date();
    fetch("/api/time-sync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            h: now.getHours(),
            m: now.getMinutes(),
            s: now.getSeconds()
        })
    }).catch(err => console.warn("Falha no time sync:", err));
}

// Sincroniza ao carregar e depois a cada 30 segundos
sincronizarHorario();
setInterval(sincronizarHorario, 30000);

// --- Toast ---

export function showToast(mensagem, isErro = false) {
    // Cria o container se não existir
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    // Cria o elemento toast
    const toast = document.createElement('div');
    toast.className = `toast ${isErro ? 'error' : ''}`;
    toast.textContent = mensagem;
    
    container.appendChild(toast);

    // Efeito de entrada (timeout garante que o CSS seja aplicado)
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);

    // Remove após 3 segundos
    setTimeout(() => {
        toast.classList.remove('show');
        // Remove do DOM após a animação de saída
        setTimeout(() => toast.remove(), 300); 
    }, 3000);
}

// --- Funções de UI (Status ESP) ---

// Função para definir como Conectado (ON)
export function setStatusConnected() {
    if (!statusContainer) return;
    statusContainer.className = 'status-container status-online';
    statusText.textContent = 'ESP8266 Conectado';
}

// Função para definir como Desconectado (OFF)
export function setStatusDisconnected() {
    if (!statusContainer) return;
    statusContainer.className = 'status-container status-offline';
    statusText.textContent = 'ESP8266 Desconectado';
}

// Função para definir como Carregando
export function setStatusLoading() {
    if (!statusContainer) return;
    statusContainer.className = 'status-container status-loading';
    statusText.textContent = 'Aguardando conexão...';
}

// --- Funções de UI (Status BW16) ---
export function setBW16Connected() {
    if (!bw16Container) return;
    bw16Container.className = 'status-container status-online';
    bw16Text.textContent = 'BW16 Conectado';
}

export function setBW16Disconnected() {
    if (!bw16Container) return;
    bw16Container.className = 'status-container status-offline';
    bw16Text.textContent = 'BW16 Desconectado';
}

export function setBW16Loading() {
    if (!bw16Container) return;
    bw16Container.className = 'status-container status-loading';
    bw16Text.textContent = 'Aguardando BW16...';
}

// --- Requisições ao ESP ---
export async function verificarStatusESP() {
    try {
        const res = await fetch('/status-esp', { cache: 'no-store' });
        if (res.ok) setStatusConnected();
        else setStatusDisconnected();
    } catch (e) {
        setStatusDisconnected();
    }
}

export async function verificarStatusBW16() {
    try {
        const res = await fetch("/status-bw16");
        if (!res.ok) {
            setBW16Disconnected();
            return false;
        }
        
        const data = await res.json();
        
        if (data.conectado) {
            setBW16Connected();
            return true;
        } else {
            setBW16Disconnected();
            return false;
        }
    } catch (e) {
        console.warn("Não foi possível verificar status do BW16:", e);
        setBW16Disconnected();
        return false;
    }
}

// --- Inicialização Global ---
// Já inicia o loop de verificação assim que o arquivo é importado
export function iniciarMonitoramentoStatus() {
    setStatusLoading();
    setBW16Loading();
    verificarStatusBW16();
    verificarStatusESP();
    
    // Atualiza a cada 5 segundos
    setInterval(verificarStatusBW16, 5000);
    setInterval(verificarStatusESP, 5000);
}
export const evtSource = new EventSource("/events");


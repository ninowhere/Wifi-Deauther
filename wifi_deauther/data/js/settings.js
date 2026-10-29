import { iniciarMonitoramentoStatus, showToast } from './common.js';

iniciarMonitoramentoStatus();


// Seletores
const btnSalvar = document.getElementById('btn-salvar');
const btnResetar = document.getElementById('btn-resetar');
const campos = {
    tempoInicial: document.getElementById('tempo-inicial'),
    tempoAtaque: document.getElementById('tempo-ataque'),
    tempoDurante: document.getElementById('tempo-durante'),
    timeoutDispositivo: document.getElementById('timeout-dispositivo'),
    ssid: document.getElementById('ssid'),
    senha: document.getElementById('senha')
};

// Valores padrão
const padroes = {
    tempoInicial: 12,
    tempoAtaque: 10,
    tempoDurante: 6,
    //imeoutDispositivo: 5
    ssid: "", 
    senha: ""
};

// Carrega valores salvos (se existirem)
function carregarConfiguracoes() {
    const configSalva = localStorage.getItem('config_tempos');
    if (configSalva) {
        const c = JSON.parse(configSalva);
        campos.tempoInicial.value = c.tempoInicial || padroes.tempoInicial;
        campos.tempoAtaque.value = c.tempoAtaque || padroes.tempoAtaque;
        campos.tempoDurante.value = c.tempoDurante || padroes.tempoDurante;
        //campos.timeoutDispositivo.value = config.timeoutDispositivo;
        if (c.ssid) campos.ssid.value = c.ssid;
        if (c.senha) campos.senha.value = c.senha;
    }
}

// Salva no localStorage e envia para o ESP8266
async function salvarConfiguracoes() {
    const config = {
        tempoInicial: parseInt(campos.tempoInicial.value) || padroes.tempoInicial,
        tempoAtaque: parseInt(campos.tempoAtaque.value) || padroes.tempoAtaque,
        tempoDurante: parseInt(campos.tempoDurante.value) || padroes.tempoDurante,
        ssid: campos.ssid.value,
        senha: campos.senha.value
        //timeoutDispositivo: parseInt(campos.timeoutDispositivo.value) || padroes.timeoutDispositivo
    };

    localStorage.setItem('config_tempos', JSON.stringify(config));

    try {
        const response = await fetch('/api/configurar-tempos', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        if (!response.ok) {
            throw new Error('Erro na resposta do servidor');
        }

        const result = await response.text();
        showToast('Configurações salvas e enviadas!');
        console.log('Resposta do ESP:', result);
    } catch (error) {
        console.error('Falha ao enviar configurações:', error);
        showToast('Salvo no navegador, mas falha ao enviar para o ESP8266.', true);
    }
}

// Restaura padrões
function resetarConfiguracoes() {
    campos.tempoInicial.value = padroes.tempoInicial;
    campos.tempoAtaque.value = padroes.tempoAtaque;
    campos.tempoDurante.value = padroes.tempoDurante;
    //campos.timeoutDispositivo.value = padroes.timeoutDispositivo;
    localStorage.removeItem('config_tempos');
    showToast('Padrões restaurados.');
}

// Eventos
btnSalvar.addEventListener('click', salvarConfiguracoes);
btnResetar.addEventListener('click', resetarConfiguracoes);

// Inicializa os campos
carregarConfiguracoes();
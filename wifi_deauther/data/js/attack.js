import { evtSource, iniciarMonitoramentoStatus, horaAgora, showToast, SwalDark } from './common.js';
const consoleBody = document.getElementById("console-output");
let arrayRedes = [];
let bssidAtual = null;              // BSSID sendo testado no momento
let vulnerabilidades = {};          // Mapa: bssid -> true (vulnerável) / false (protegida)

iniciarMonitoramentoStatus();

evtSource.addEventListener("log", (e) => {
    const mensagem = e.data;

    const linha = document.createElement("div");
    linha.className = "log-entry";

    // Timestamp com cor própria
    const ts = document.createElement("span");
    ts.className = "log-time";
    ts.textContent = horaAgora();

    // Mensagem com cor própria
    const msg = document.createElement("span");
    msg.className = "log-msg";
    msg.textContent = e.data;

    linha.appendChild(ts);
    linha.appendChild(document.createTextNode(" "));
    linha.appendChild(msg);

    consoleBody.appendChild(linha);
    consoleBody.scrollTop = consoleBody.scrollHeight;

    // Extrai BSSID de mensagens relevantes
    const regexInicio = /Ataque iniciado para teste de vulnerabilidade em (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})/;
    const regexVulneravel = /Rede (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}) VULNERÁVEL!/;
    const regexProtegida = /Rede (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}) não apresentou queda/;

    let match = mensagem.match(regexInicio);
    if (match) {
        bssidAtual = match[1];
    }

    match = mensagem.match(regexVulneravel);
     if (match) {
        // Verifica se já não foi marcada como vulnerável antes (para não abrir o alerta várias vezes)
        if (!vulnerabilidades[match[1]]) {
            vulnerabilidades[match[1]] = true;
            
            // --- NOVO: SWEETALERT DE DEFESA ---
            SwalDark.fire({
                icon: 'warning',
                title: 'Rede Vulnerável Detectada!',
                html: `A rede <b>${match[1]}</b> sofre um ataque deauth.<br><br>
                       Esse tipo de ataque abre portas para ataques mais perigosos.<br>
                       Deseja aprender como se proteger disso?`,
                showCancelButton: true,
                confirmButtonText: '🛡️ Como se Defender',
                cancelButtonText: 'Fechar',
                confirmButtonColor: '#7CD650',
                cancelButtonColor: '#555',
                reverseButtons: true,
                focusCancel: true,
                allowOutsideClick: false
            }).then((result) => {
                if (result.isConfirmed) {
                    window.location.href = 'howtoprotect.html'; // Redireciona para a nova página
                }
            });
            // ----------------------------------
        }
        bssidAtual = null; // teste concluído
    }

    match = mensagem.match(regexProtegida);
    if (match) {
        vulnerabilidades[match[1]] = false;
        bssidAtual = null;
    }

    // Re-renderiza a tabela para refletir mudanças
    renderizarTabelaCompleta();

    
});

function limparConsole() {
    consoleBody.innerHTML = "";
}

document.addEventListener("DOMContentLoaded", () => {
    const redesSalvas = localStorage.getItem("redes_selecionadas");

    if (redesSalvas) {
        arrayRedes = JSON.parse(redesSalvas);
        renderizarTabelaCompleta(); // Renderiza as redes armazenadas imediatamente
    }
});
function renderizarTabelaCompleta() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = ""; // Limpa a tabela

    arrayRedes.forEach(data => {
        const row = tbody.insertRow();
        const rowId = "net-" + data.bssid.replace(/:/g, '-');
        row.id = rowId;

        // Determina o status de vulnerabilidade
        let statusVulneravel = '—'; // padrão (não testado)
        if (vulnerabilidades[data.bssid] === true) {
            statusVulneravel = '⚠️ Vulnerável';
        } else if (vulnerabilidades[data.bssid] === false) {
            statusVulneravel = '🛡️ Protegida';
        }

        // Monta a linha
        row.innerHTML = `
            <td>${data.bssid}</td>
            <td>${data.ssid}</td>
            <td>${data.chan}</td>
            <td>${statusVulneravel}</td>
        `;

        // Adiciona destaque se for a rede em teste
        if (data.bssid === bssidAtual) {
            row.classList.add('row-testing');
        }
    });
}

//Botão Parar
document.getElementById("btn-parar").addEventListener("click", function () {
    fetch("/parar", {
        method: "POST"
    })
        .then(response => {
            if (response.ok) {
                showToast("Envio interrompido!");
            } else {
                showToast("Erro ao parar.", true);
            }
        })
        .catch(error => {
            console.error("Erro:", error);
            showToast("Falha na comunicação.", true);
        });
        bssidAtual = null;           // remove destaque
        renderizarTabelaCompleta();  // atualiza a tabela
        localStorage.removeItem('redes_selecionadas');
})
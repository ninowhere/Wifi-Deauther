import { iniciarMonitoramentoStatus, evtSource, horaAgora, showToast } from './common.js';

iniciarMonitoramentoStatus();

const consoleOutput = document.getElementById('console-output');

// --- Função para escapar HTML e evitar injeção ---
function escapeHtml(s) {
    return s.replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
}

// --- Carrega o histórico do ESP ---
async function carregarLogsHistoricos() {
    if (!consoleOutput) return;
    try {
        const res = await fetch("/api/logs");
        const texto = await res.text();
        
        consoleOutput.innerHTML = ""; // Limpa tela

        texto.split("\n").forEach(linhaCrua => {
            if (!linhaCrua.trim()) return;
            
            // Separa o timestamp (se existir) da mensagem
            const m = linhaCrua.match(/^(\[\d{2}:\d{2}:\d{2}\])\s*(.*)$/);
            const tsTexto = m ? m[1] : "[--:--:--]";
            const msgTexto = m ? m[2] : linhaCrua;

            const div = document.createElement("div");
            div.className = "log-entry";
            div.innerHTML = `
                <span class="log-time">${escapeHtml(tsTexto)}</span> 
                <span class="log-msg">${escapeHtml(msgTexto)}</span>
            `;
            consoleOutput.appendChild(div);
        });
        
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
    } catch (err) {
        console.error("Erro ao carregar logs:", err);
    }
}

// --- SSE ao vivo ---
evtSource.addEventListener("log", (e) => {
    if (!consoleOutput) return;
    
    const linha = document.createElement("div");
    linha.className = "log-entry";
    
    const ts = document.createElement("span");
    ts.className = "log-time";
    ts.textContent = horaAgora();
    
    const msg = document.createElement("span");
    msg.className = "log-msg";
    msg.textContent = e.data;
    
    linha.appendChild(ts);
    linha.appendChild(document.createTextNode(" "));
    linha.appendChild(msg);
    
    consoleOutput.appendChild(linha);
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
});

// --- Botões de Ação ---
document.getElementById("btn-baixar-log")?.addEventListener("click", () => {
    window.location.href = "/download/logs.txt";
});

document.getElementById("btn-limpar-log")?.addEventListener("click", async () => {
    if (!confirm("Apagar todos os logs do ESP?")) return;
    try {
        await fetch("/api/logs/clear", { method: "POST" });
        if (consoleOutput) consoleOutput.textContent = "";
    } catch (e) {
        showToast("Erro ao limpar logs.");
    }
});

// Inicializa a página
carregarLogsHistoricos();
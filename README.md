# Firawynix Monitor

Aplicação desktop para **Windows** que monitora e gerencia, em tempo real, os serviços
**systemd** e os contêineres **Docker** de um ou mais servidores Linux — sem instalar
nenhum agente: tudo acontece por **SSH** (Paramiko), com autenticação por chave.

![Painel principal (modo demonstração)](docs/screenshot.png)

## Recursos

| Área | O que faz |
|---|---|
| Descoberta | `systemctl list-units --type=service --all --output=json` (com fallback automático para a saída tabular em systemd antigos) e `docker ps -a --format '{{json .}}'` |
| Status | **Ativo**, **Parado**, **Falha**, **Iniciando** — inclusive contêineres `unhealthy` e em loop de reinício |
| Métricas | CPU (delta de `/proc/stat`), load average, RAM (`free -m`), discos (`df`), uptime |
| Interface | Seletor de servidor, cartões de métricas, tabela com filtros (Todos / Ativos / Com Falha / Parados / Iniciando), filtro por tipo, busca instantânea e ordenação por coluna |
| Ações | **Iniciar**, **Parar**, **Reiniciar** (com confirmação) e **Ver Logs** (`journalctl -u <serviço> -n 50 --no-pager` ou `docker logs`) em janela modal |
| Bandeja | Ícone no *system tray* (pystray) que muda de cor conforme a saúde; fechar a janela mantém o monitor rodando em segundo plano |
| Alertas | *Toasts* nativos do Windows (win11toast → plyer → balão da bandeja) quando um serviço crítico falha, se recupera ou um servidor fica inacessível |
| Resiliência | Uma thread por servidor, reconexão com *exponential backoff* + *jitter*, **timeout máximo de 5 s por comando**, keepalive SSH e watchdog contra servidores travados |

## Arquitetura

```
firawynix-monitor/
├── main.py                 # ponto de entrada: CLI, logging, instância única, ciclo de vida
├── config/
│   └── settings.py         # carrega e valida servers.json (+ .env); diretórios da aplicação
├── core/
│   ├── models.py           # dataclasses imutáveis e eventos
│   ├── ssh_client.py       # conexão Paramiko, execução com timeout, construtores de comando e parsers
│   ├── monitor.py          # ServerMonitor (thread por servidor), backoff, alertas, MonitorManager
│   ├── notifier.py         # toasts do Windows com fallback e cooldown
│   └── demo.py             # servidores simulados (--demo)
├── ui/
│   ├── dashboard.py        # janela principal, tabela, filtros, diálogos e modal de logs
│   └── tray.py             # ícone da bandeja e geração dos ícones
├── tests/                  # pytest (parsers, configuração, monitor)
├── docs/sudoers.example    # regras NOPASSWD restritas
├── FirawynixMonitor.spec   # PyInstaller
├── scripts/build.ps1       # build do .exe em um comando
├── requirements.txt        # dependências de execução congeladas
└── requirements-dev.txt    # + testes e empacotamento
```

### Fluxo de dados e threads

```
 ┌──────────────── thread por servidor ────────────────┐
 │ ServerMonitor: conecta (backoff) → coleta → compara │──┐  eventos
 └─────────────────────────────────────────────────────┘  │ (queue.Queue)
 ┌──────────── ThreadPoolExecutor (4 workers) ─────────┐  │
 │ ações (start/stop/restart) e leitura de logs        │──┤
 └─────────────────────────────────────────────────────┘  ▼
                                    Dashboard._pump() a cada 100 ms (thread da UI)
 pystray (thread própria) ── call_in_ui() ──────────────▲
```

* A interface **nunca** executa SSH: ela só consome eventos (`ConnectionEvent`,
  `SnapshotEvent`, `ServiceAlertEvent`, `ActionResultEvent`) e *futures*.
* Os callbacks da bandeja nunca tocam no Tkinter; eles enfileiram funções para a
  thread da UI.
* Cada coleta faz **3 round-trips** (serviços, Docker, métricas). Uptime, load, CPU,
  memória e disco vêm de um único comando.
* Um comando que passa de 5 s é abortado (`SSHCommandTimeout`); os dados anteriores
  continuam na tela com aviso. Três timeouts seguidos derrubam a conexão e o monitor
  reconecta. Um *watchdog* fecha o transporte se o servidor travar no meio do
  protocolo SSH.
* Falhas de autenticação ou de chave de host usam um backoff bem mais longo
  (30 s → 10 min) para não disparar o fail2ban do servidor.

## Requisitos

* Windows 10 ou 11 (x64)
* Python **3.11+** (todas as dependências têm wheels Windows para 3.11–3.14) — apenas para rodar a partir
  do código-fonte ou gerar o `.exe`
* Nos servidores: OpenSSH, `systemd` e, opcionalmente, Docker. Nada é instalado neles.

## Instalação (código-fonte)

```powershell
git clone https://github.com/firawynix/firawynix-monitor.git
cd firawynix-monitor
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

Copy-Item servers.example.json servers.json   # edite com seus servidores
python main.py
```

Quer só conhecer a interface? `python main.py --demo` usa servidores simulados (sem SSH).

### Opções de linha de comando

| Opção | Efeito |
|---|---|
| `--config CAMINHO` | Usa outro `servers.json` |
| `--minimized` | Inicia oculto na bandeja (útil na inicialização do Windows) |
| `--demo` | Servidores simulados, sem SSH |
| `--debug` | Log detalhado |
| `--version` | Mostra a versão |

## Configuração

### Onde fica o `servers.json`

Procurado nesta ordem:

1. `--config C:\caminho\servers.json`
2. variável de ambiente `FIRAWYNIX_CONFIG`
3. pasta do executável (ou raiz do projeto, rodando pelo código-fonte)
4. pasta atual
5. `%APPDATA%\FirawynixMonitor\servers.json`

### Exemplo

```json
{
  "settings": {
    "poll_interval_seconds": 5,
    "command_timeout_seconds": 5,
    "minimize_to_tray": true,
    "appearance_mode": "dark",
    "log_lines": 50,
    "notifications": {
      "enabled": true,
      "notify_on_recovery": true,
      "notify_on_disconnect": true,
      "alert_on_stop": false,
      "cooldown_seconds": 120
    }
  },
  "servers": [
    {
      "name": "prod-web-01",
      "host": "192.168.10.21",
      "username": "monitor",
      "key_file": "~/.ssh/id_ed25519",
      "key_passphrase_env": "PROD_WEB_KEY_PASSPHRASE",
      "critical_services": ["nginx", "postgresql*", "docker:api"],
      "exclude_services": ["systemd-*", "getty@*"]
    },
    {
      "name": "staging",
      "host": "staging.example.com",
      "port": 2222,
      "username": "deploy",
      "password_env": "STAGING_SSH_PASSWORD",
      "host_key_policy": "strict",
      "docker": "off"
    }
  ]
}
```

O arquivo completo está em [`servers.example.json`](servers.example.json). Chaves
desconhecidas geram erro (um `"usename"` digitado errado não passa despercebido) e
todos os problemas são listados de uma vez ao iniciar.

### `settings`

| Campo | Padrão | Descrição |
|---|---|---|
| `poll_interval_seconds` | `5` | Intervalo entre coletas (2–3600 s). Também pode ser trocado na interface |
| `command_timeout_seconds` | `5` | Timeout de cada comando SSH. **Máximo 5** |
| `connect_timeout_seconds` | `5` | Timeout de conexão/handshake/autenticação |
| `minimize_to_tray` | `true` | Fechar a janela mantém o monitor na bandeja |
| `start_minimized` | `false` | Inicia oculto na bandeja |
| `appearance_mode` | `"dark"` | `dark`, `light` ou `system` |
| `log_lines` | `50` | Linhas iniciais no modal de logs |
| `known_hosts_file` | `%LOCALAPPDATA%\FirawynixMonitor\known_hosts` | Onde as chaves de host aceitas são gravadas |
| `notifications.enabled` | `true` | Liga/desliga os toasts |
| `notifications.notify_on_recovery` | `true` | Avisa quando um serviço/servidor se recupera |
| `notifications.notify_on_disconnect` | `true` | Avisa quando um servidor fica inacessível |
| `notifications.alert_on_stop` | `false` | Também alerta quando um serviço crítico **para** (sem falhar). Paradas feitas pelo próprio monitor não geram alerta |
| `notifications.cooldown_seconds` | `120` | Intervalo mínimo entre alertas iguais |
| `notifications.app_id` | — | AppUserModelID dos toasts (opcional, veja *Solução de problemas*) |

### `servers[]`

| Campo | Padrão | Descrição |
|---|---|---|
| `name` | — | Nome exibido (único) |
| `host` / `port` | — / `22` | Endereço SSH |
| `username` | — | Usuário SSH (recomendado: usuário dedicado, ex. `monitor`) |
| `key_file` | — | Chave privada (`~` e `%VAR%` são expandidos). Sem ela, usa o agente SSH e as chaves padrão de `~/.ssh` (`id_ed25519`, `id_rsa`, ...) |
| `key_passphrase_env` | — | **Nome** da variável de ambiente com a passphrase da chave |
| `password_env` | — | **Nome** da variável de ambiente com a senha SSH |
| `allow_agent` / `look_for_keys` | `true` | Usa o agente (OpenSSH do Windows / Pageant) e as chaves padrão |
| `host_key_policy` | `"accept-new"` | `accept-new`: aceita e grava na 1ª conexão (como o OpenSSH); `strict`: só conecta a hosts já presentes no `known_hosts`. Em ambos os modos uma chave **diferente** da gravada é sempre recusada |
| `use_sudo` | `true` | Usa `sudo -n` para iniciar/parar/reiniciar serviços (ignorado se `username` for `root`) |
| `docker` | `"auto"` | `auto` (detecta), `on` (avisa se indisponível) ou `off` |
| `docker_sudo` | `false` | Usa `sudo -n` com o Docker |
| `logs_sudo` | `false` | Usa `sudo -n` com o `journalctl` |
| `poll_interval_seconds` | global | Intervalo específico deste servidor |
| `critical_services` | `["*"]` | Padrões *glob* dos serviços que geram alerta. `nginx` casa com `nginx.service`; prefixe com `docker:` ou `systemd:` para restringir o tipo |
| `exclude_services` | `[]` | Padrões ocultados da tabela e dos alertas |

### Segredos (`.env`)

Senhas e passphrases **nunca** ficam no `servers.json` — chaves como `password`,
`passphrase` ou `sudo_password` são recusadas na validação. Informe apenas o **nome**
da variável e defina o valor:

* nas variáveis de ambiente do Windows, **ou**
* em um arquivo `.env` ao lado do `servers.json` ou do executável (veja
  [`.env.example`](.env.example)). Variáveis já definidas no sistema têm prioridade.

## Preparando os servidores Linux

1. **Usuário dedicado com chave:**

   ```bash
   sudo useradd -m -s /bin/bash monitor
   sudo -u monitor mkdir -m 700 -p ~monitor/.ssh
   # cole a chave pública (id_ed25519.pub) gerada no Windows com: ssh-keygen -t ed25519
   sudo -u monitor tee -a ~monitor/.ssh/authorized_keys < id_ed25519.pub
   sudo chmod 600 ~monitor/.ssh/authorized_keys
   ```

2. **Leitura de logs sem sudo:** `sudo usermod -aG systemd-journal monitor`

3. **Docker (opcional):** `sudo usermod -aG docker monitor` — atenção: o grupo
   `docker` equivale a acesso root. Alternativa: `"docker_sudo": true` com regras
   NOPASSWD específicas.

4. **Ações sem senha, apenas para os comandos necessários** — o monitor usa
   `sudo -n` (não interativo) e **nunca** envia senha ao sudo. Crie
   `/etc/sudoers.d/firawynix-monitor` com `sudo visudo -f /etc/sudoers.d/firawynix-monitor`
   a partir de [`docs/sudoers.example`](docs/sudoers.example). Exemplo mínimo:

   ```sudoers
   Cmnd_Alias FWX_NGINX = /usr/bin/systemctl --no-block start nginx.service, \
                          /usr/bin/systemctl --no-block stop nginx.service, \
                          /usr/bin/systemctl --no-block restart nginx.service
   monitor ALL=(root) NOPASSWD: FWX_NGINX
   ```

   Os comandos são executados com `--no-block`: o systemd enfileira o job e responde
   na hora; serviços lentos aparecem como **Iniciando** na coleta seguinte, sem estourar
   o limite de 5 s. Se o sudoers não liberar um comando, a interface mostra
   exatamente isso (em vez de travar esperando uma senha).

## Uso

* **Servidor**: escolha no seletor do topo (um `●` ao lado do nome indica problema).
* **Tabela**: clique nos cabeçalhos para ordenar; falhas ficam no topo por padrão.
* **Filtros**: status, tipo (systemd/Docker) e busca (`Ctrl+F`; `Esc` limpa). Vários
  termos são combinados com "E".
* **Ações**: selecione uma linha e use os botões ou o menu de contexto (botão direito).
  Duplo clique ou `Enter` abrem os logs. `F5` força uma coleta.
* **Bandeja**: fechar a janela mantém o monitor rodando. O ícone fica verde (tudo ok),
  amarelo (avisos), vermelho (serviço crítico com falha ou servidor inacessível) ou
  cinza (conectando). Menu: *Abrir painel*, *Atualizar agora*, *Silenciar alertas*,
  *Sair*.
* **Logs da aplicação**: `%LOCALAPPDATA%\FirawynixMonitor\logs\monitor.log`
  (rotativo, 3 × 1 MB).

## Empacotamento (`.exe` com PyInstaller)

Em um PowerShell na raiz do projeto:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

O script cria `.venv`, instala `requirements-dev.txt`, roda os testes e gera
**`dist\FirawynixMonitor.exe`** (arquivo único, sem console, com ícone e informações de
versão). Manualmente:

```powershell
pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean FirawynixMonitor.spec
```

Distribua o `.exe` com um `servers.json` na mesma pasta (e, se usar, o `.env`).

**Iniciar junto com o Windows** (minimizado na bandeja):

```powershell
$exe = (Resolve-Path dist\FirawynixMonitor.exe).Path
$lnk = Join-Path ([Environment]::GetFolderPath("Startup")) "Firawynix Monitor.lnk"
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
$s.TargetPath = $exe; $s.Arguments = "--minimized"; $s.WorkingDirectory = Split-Path $exe
$s.Save()
```

## Segurança

* **Sem agente**: nada é instalado nos servidores; apenas comandos de leitura e as
  ações explicitamente confirmadas pelo usuário.
* **Sem segredos em texto plano**: `servers.json` só referencia variáveis de ambiente.
* **Sem senha de sudo**: sempre `sudo -n`; libere o mínimo via sudoers (NOPASSWD).
* **Chaves de host verificadas**: TOFU (`accept-new`) ou `strict`; chave divergente é
  recusada com alerta de possível *man-in-the-middle*.
* **Sem injeção de comandos**: nomes de serviço/contêiner são validados por whitelist
  (não podem começar com `-`) e sempre passam por `shlex.quote`; os comandos rodam via
  `sh -c` com `LC_ALL=C`.
* **Instância única** (mutex do Windows) e logs sem credenciais.

## Testes

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

Os testes cobrem os parsers (formatos modernos e legados de `systemctl`, `docker ps`,
`free`, `df`), a validação da configuração, a política de alertas, o backoff e o loop
do monitor (reconexão, perda de conexão, timeouts) com um cliente SSH falso.

## Solução de problemas

| Sintoma | Causa / solução |
|---|---|
| "O sudo exigiu senha" | O comando não está liberado com NOPASSWD. Confira o caminho do `systemctl` (`command -v systemctl`) e o texto exato do comando em `docs/sudoers.example` |
| "Interactive authentication required" | `use_sudo` está desligado e o polkit negou. Ligue `use_sudo` e configure o sudoers |
| Logs incompletos ("not seeing messages from other users") | Adicione o usuário ao grupo `systemd-journal` (ou use `logs_sudo`) |
| "Sem permissão no socket do Docker" | Grupo `docker` ou `docker_sudo: true` |
| "A chave SSH ... MUDOU" | O servidor foi reinstalado ou há interceptação. Se for legítimo, remova a linha do host em `%LOCALAPPDATA%\FirawynixMonitor\known_hosts` (e em `~/.ssh/known_hosts`) |
| "ausente do known_hosts (strict)" | Conecte uma vez com `ssh usuario@host` e confirme a chave |
| Aviso "systemctl não respondeu a tempo" | Servidor sobrecarregado; os últimos dados continuam visíveis. Após 3 timeouts seguidos o monitor reconecta |
| Toasts não aparecem | Verifique *Configurações > Sistema > Notificações* e o modo *Não incomodar*. Para exibir outro nome de aplicativo, defina `notifications.app_id` com um AppUserModelID registrado (ex.: o de um atalho no Menu Iniciar) |
| Janela não reabre | Use o ícone da bandeja (pode estar em "Mostrar ícones ocultos"). Uma segunda instância não é aberta de propósito |

## Atualizando dependências

As versões em `requirements*.txt` são exatas (incluindo as transitivas) para builds
reprodutíveis. Para atualizar:

```powershell
python -m venv .venv-upd; .\.venv-upd\Scripts\Activate.ps1
pip install customtkinter paramiko pystray Pillow win11toast plyer python-dotenv pytest pyinstaller
pip freeze   # atualize os pinos de requirements.txt / requirements-dev.txt
python -m pytest
```

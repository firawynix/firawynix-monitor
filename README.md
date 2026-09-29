# Firawynix Monitor

Aplicação desktop para **Windows** (tema **ciano**, claro ou escuro) que monitora e
gerencia, em tempo real, servidores Linux e **VPS**: serviços e demais unidades
**systemd**, contêineres **Docker**, **Podman** e **LXD/Incus**, stacks do **Compose**,
pods **Kubernetes** (inclusive k3s/microk8s), **VMs libvirt/KVM**, processos, portas,
agendamentos, eventos do journal, **auditoria de segurança** (SSH, firewall, fail2ban,
logins, sudo), **saúde dos discos (SMART)**, **sites e certificados TLS**, franquia de
tráfego e a saúde do host, com **histórico em gráficos**. Não instala nenhum agente nos
servidores: tudo acontece por **SSH** (Paramiko). Integra-se à **API do Windows**
(Gerenciador de Credenciais, Visualizador de Eventos, barra de tarefas, inicialização,
energia e ICMP).

![Painel de um servidor (modo demonstração)](docs/screenshot.png)

## Recursos

| Área | O que faz |
|---|---|
| **Visão geral** | Todos os servidores lado a lado (saúde, CPU, memória, disco, load, rede, **latência**, uptime, cargas ativas/falhas, contêineres/pods/VMs, **nota de segurança**, alertas) e uma lista única de **problemas em todos os servidores** (cargas, endpoints fora do ar, discos com SMART ruim, falhas críticas de segurança); duplo clique leva ao item |
| **Serviços** | Unidades systemd (`service`, `timer`, `socket`, `mount`, `path`), contêineres Docker/Podman, **instâncias LXD/Incus** (contêineres e VMs), pods Kubernetes e VMs libvirt em uma só tabela, com CPU/memória por serviço (cgroup v2), por contêiner (`stats`) e por instância LXD; filtros por status e tipo, busca e ordenação |
| **Stacks** | Projetos do Docker/Podman **Compose**, pods do Podman e namespaces do Kubernetes, com status agregado (ativo/degradado/falha), membros, diretório/arquivos do Compose e ações na stack inteira |
| **Processos** | Top N por CPU (CPU instantânea via `/proc`), memória, RSS, tempo, linha de comando; encerrar com TERM/KILL (desativado por padrão) |
| **Rede** | Taxas por interface (física/virtual), portas em escuta com processo e exposição (todas as interfaces / local), conexões TCP/UDP |
| **VPS** | Plataforma/provedor (DigitalOcean, Hetzner, Vultr, AWS, Azure, Google, OVH, Contabo, OpenStack, Proxmox…), **CPU steal** e iowait, **latência Windows → servidor**, relógio/**NTP** (e desvio do chrony), DNS, gateway, IPs públicos/privados, swap e *swappiness*, **OOM killer** (24 h), **tráfego do mês e franquia** (vnStat) e **endpoints**: sites/APIs (status HTTP, latência) e **certificados TLS** (validade, emissor, dias para expirar) verificados a partir do Windows |
| **Segurança** | **Nota de 0 a 100** e verificações com explicação e recomendação: login do root e por senha no SSH (configuração efetiva, com `Include`), chaves autorizadas fracas, firewall (UFW, firewalld, nftables, iptables), **serviços sensíveis expostos** (Redis, bancos, API do Docker… inclusive portas do Docker que ignoram o UFW), fail2ban/CrowdSec, tentativas de login, atualizações de segurança e automáticas, reinício pendente, AppArmor/SELinux, *hardening* do kernel (sysctl), contas com UID 0, sudo negado, `/tmp`, NTP, auditd. Abas de **tentativas SSH por IP** (com **banir**), **fail2ban** (com **desbanir**), **logins aceitos**, **uso de sudo**, sessões abertas e chaves autorizadas (tipo, bits, impressão digital) |
| **Agendamentos** | Timers do systemd (próxima/última execução) e entradas de cron (usuário, `/etc/crontab`, `/etc/cron.d`, `cron.daily`…) |
| **Eventos** | Erros do journal nas últimas N horas (`journalctl -p err -o json`), com busca e detalhes |
| **Sistema** | SO, kernel, CPU, virtualização, boot, IPs, reinício pendente, **atualizações pendentes** (apt/dnf/yum/apk/zypper, só cache local), falhas de login SSH (24 h), temperaturas, discos com uso de **inodes**, E/S por disco, **saúde SMART** (ATA e NVMe: aprovado/reprovado, setores realocados/pendentes, desgaste, temperatura, horas ligado) e estado de cada runtime |
| **Histórico** | Gráficos de CPU/memória/disco, load, rede, E/S de disco, **CPU steal/iowait** e **latência** (15 min a 7 dias), gravados em SQLite local; crosshair com tooltip e exportação CSV |
| **Ações** | Iniciar/Parar/Reiniciar (unidades, contêineres, instâncias LXD, VMs), reiniciar pod (recriar), ações em stacks inteiras, **banir/desbanir IP no fail2ban**, logs/detalhes em janela modal, **Terminal SSH** em um clique |
| **Alertas** | Toasts do Windows quando um item crítico falha/recupera, um servidor cai ou volta, **CPU/memória/disco/steal/latência** passam do limite, um **site sai do ar** ou um **certificado vai expirar**, um **disco degrada**, surge uma **falha crítica de segurança**, o **root faz login**, o **OOM killer** age ou a **franquia de tráfego** chega a 80%/100%; ícone na bandeja muda de cor |
| **API do Windows** | Senhas SSH no **Gerenciador de Credenciais** (DPAPI), alertas e ações no **Visualizador de Eventos**, **barra de título** na cor do tema (Windows 11), **piscar a barra de tarefas** em alertas críticos, **iniciar com o Windows**, **impedir a suspensão** e **ping ICMP** sem administrador |
| **Exportação** | Qualquer tabela para CSV (botão direito → *Exportar tabela*), pronto para o Excel |
| **Resiliência** | Uma thread por servidor, coletores em paralelo, reconexão com *exponential backoff*, **timeout máximo de 5 s por comando**, keepalive e watchdog; endpoints verificados em segundo plano |

| Visão geral | Segurança | VPS |
|---|---|---|
| ![Visão geral](docs/screenshot-visao-geral.png) | ![Segurança](docs/screenshot-seguranca.png) | ![VPS](docs/screenshot-vps.png) |

| Histórico | Sistema (SMART) | Tema claro |
|---|---|---|
| ![Histórico](docs/screenshot-historico.png) | ![Sistema](docs/screenshot-sistema.png) | ![Tema claro](docs/screenshot-claro.png) |

## Arquitetura

```
firawynix-monitor/
├── main.py                 # ponto de entrada: CLI, logging, instância única, ciclo de vida
├── config/
│   ├── settings.py         # carrega e valida servers.json (+ .env / Gerenciador de Credenciais)
│   └── preferences.py      # preferências alteradas pela interface (preferences.json)
├── core/
│   ├── models.py           # dataclasses imutáveis (cargas, stacks, métricas, VPS, segurança, eventos)
│   ├── commands.py         # construtores de comandos remotos (validação + shlex.quote + sudo -n)
│   ├── parsers.py          # parsers de systemctl, docker/podman, incus/lxc, kubectl, virsh, /proc, ss,
│   │                       #   sshd, fail2ban, journal, smartctl, vnStat, cron…
│   ├── security.py         # regras da auditoria de segurança e nota 0–100
│   ├── endpoints.py        # HTTP, certificados TLS e portas TCP verificados a partir do Windows
│   ├── alerts.py           # alertas de endpoints, SMART, segurança, logins, OOM e franquia
│   ├── winapi.py           # API do Windows via ctypes (credenciais, eventos, DWM, ICMP…)
│   ├── ssh_client.py       # conexão Paramiko, execução com timeout rígido, operações de alto nível
│   ├── monitor.py          # ServerMonitor (thread por servidor, camadas de coleta), MonitorManager
│   ├── history.py          # histórico em SQLite com retenção, agregação e migração
│   ├── notifier.py         # toasts do Windows com fallback e cooldown
│   └── demo.py             # servidores simulados (--demo)
├── ui/
│   ├── dashboard.py        # janela principal, cartões, eventos, alertas, bandeja, terminal
│   ├── tabs.py             # Serviços, Stacks, Processos, Rede, Agendamentos, Eventos, Sistema, Histórico
│   ├── vps_tab.py          # aba VPS (provedor, NTP, tráfego, endpoints)
│   ├── security_tab.py     # aba Segurança (nota, verificações, fail2ban, logins, sudo, chaves)
│   ├── options.py          # diálogo "Windows ⚙" (integrações e credenciais)
│   ├── theme.py            # tokens do tema ciano (claro/escuro) e barra de título
│   ├── themes/cyan.json    # tema do CustomTkinter
│   ├── widgets.py          # tabela genérica, cartões, diálogos, visualizador de texto, gráfico de linhas
│   └── tray.py             # ícone da bandeja e geração dos ícones
├── tests/                  # pytest
├── docs/sudoers.example    # regras NOPASSWD restritas
├── FirawynixMonitor.spec   # PyInstaller
├── scripts/build.ps1       # build do .exe em um comando
├── requirements.txt        # dependências de execução congeladas
└── requirements-dev.txt    # + testes e empacotamento (também congeladas)
```

### Coleta em camadas

Cada ciclo executa **em paralelo** (canais SSH distintos na mesma conexão) os coletores
que estiverem vencidos. Cada comando continua limitado a 5 s.

| Camada | Frequência (padrão) | O que coleta |
|---|---|---|
| Rápida | `poll_interval_seconds` (5 s) | unidades systemd, CPU/memória por serviço (cgroup v2), Docker, Podman, LXD/Incus, pods, VMs, métricas do host (CPU, steal, iowait, load, memória, discos, rede, E/S) e latência |
| Detalhes | `detail_interval_seconds` (15 s) | processos, portas, `docker/podman stats` |
| Inventário | `inventory_interval_seconds` (60 s) | sistema, VPS (provedor, NTP, DNS, OOM killer, vnStat), timers, cron, eventos do journal |
| Segurança | `security_interval_seconds` (5 min) | auditoria (sshd, firewall, contas, sysctl…), fail2ban, logins SSH, sudo, SMART |
| Atualizações | `updates_interval_seconds` (30 min) | pacotes pendentes (somente cache local, nunca acessa a rede) |
| Endpoints | `endpoint_interval_seconds` (60 s) | sites/APIs, certificados e portas, **a partir do Windows** e em segundo plano (um site lento nunca atrasa a coleta SSH) |

"Atualizar" (F5) força todas as camadas. Runtimes ausentes em modo `auto` (ex.: servidor
sem Kubernetes) são re-testados só a cada 12 ciclos.

**Latência:** no Windows, `IcmpSendEcho` (ping sem administrador); se o servidor não
responder a ICMP, o monitor usa o tempo de abertura de canal SSH (um ida-e-volta na
conexão já aberta, sem processo nem linha de log no servidor — nada de conexões TCP
extras que o fail2ban poderia punir).

**Tentativas de login:** agregadas no próprio servidor com `awk` (VPS expostos recebem
dezenas de milhares por dia): uma linha por IP de origem, cada conexão contada uma vez,
compatível com o `sshd-session` do OpenSSH 9.8+. Testado com mawk, gawk e busybox.

### Fluxo de dados e threads

```
 ┌──────────────── thread por servidor ─────────────────┐
 │ ServerMonitor: conecta (backoff) → coleta em paralelo │──┐  eventos
 │ → compara → alertas → histórico (SQLite)             │  │ (queue.Queue)
 └──────────────────────────────────────────────────────┘  │
 ┌──────── pool de sondas (sem SSH): endpoints, ICMP ─────┐  │
 └──────────────────────────────────────────────────────┘  │
 ┌──────────── ThreadPoolExecutor (ações e logs) ────────┐  │
 │ start/stop/restart, stacks, kill, fail2ban, logs      │──┤
 └──────────────────────────────────────────────────────┘  ▼
                                   Dashboard._pump() a cada 100 ms (thread da UI)
 pystray (thread própria) ── call_in_ui() ───────────────▲
```

* A interface **nunca** executa SSH: ela só consome eventos e *futures*. Só a aba visível
  é redesenhada.
* Um comando que passa de 5 s é abortado; os dados anteriores continuam na tela com
  aviso. Três ciclos seguidos com timeout nos coletores rápidos derrubam a conexão e o
  monitor reconecta. Um *watchdog* fecha o transporte se o servidor travar no meio do
  protocolo SSH.
* Falhas de autenticação ou de chave de host usam backoff longo (30 s → 10 min) para não
  disparar o fail2ban. Salvar uma nova credencial reconecta na hora.
* Os alertas disparam só na **transição** e a primeira leitura vira a linha de base:
  abrir o monitor não despeja o histórico das últimas 24 h em notificações.

## Requisitos

* Windows 10 ou 11 (x64). As cores da barra de título exigem o Windows 11.
* Python **3.11+** (todas as dependências têm wheels Windows para 3.11–3.14) — apenas
  para rodar a partir do código-fonte ou gerar o `.exe`
* Nos servidores: OpenSSH e `systemd`. Docker, Podman, LXD/Incus, Kubernetes, libvirt,
  `ss`, `crontab`, `smartctl` (pacote *smartmontools*), `vnstat`, fail2ban etc. são
  detectados automaticamente e usados quando existirem. Nada é instalado neles.
* Para o botão **Terminal SSH**: o *Cliente OpenSSH* do Windows (já vem no Windows 10
  1809+ e 11). Com o Windows Terminal instalado, abre uma nova aba nele.

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

Quer só conhecer a interface? `python main.py --demo` usa cinco servidores simulados
(web em DigitalOcean com stacks Compose, fail2ban e endpoints; banco na Hetzner com
problemas de segurança e um disco degradado; cluster k3s na Vultr com CPU steal alto e um
site fora do ar; hipervisor com VMs, LXD/Incus e SMART; e um servidor offline) e
histórico de exemplo.

### Opções de linha de comando

| Opção | Efeito |
|---|---|
| `--config CAMINHO` | Usa outro `servers.json` |
| `--minimized` | Inicia oculto na bandeja (usado pela inicialização com o Windows) |
| `--demo` | Servidores simulados, sem SSH |
| `--debug` | Log detalhado |
| `--set-credential SERVIDOR` | Pede a senha SSH (sem eco, no console — use com `python main.py`) e a grava no Gerenciador de Credenciais do Windows. No `.exe`, use o botão **Windows ⚙** |
| `--delete-credential SERVIDOR` | Remove a credencial |
| `--passphrase` | Com as duas opções acima: passphrase da chave em vez da senha |
| `--version` | Mostra a versão |

## Configuração

### Onde fica o `servers.json`

Procurado nesta ordem: `--config` → variável `FIRAWYNIX_CONFIG` → pasta do executável
(ou raiz do projeto) → pasta atual → `%APPDATA%\FirawynixMonitor\servers.json`.

O arquivo completo está em [`servers.example.json`](servers.example.json). Chaves
desconhecidas geram erro (um `"usename"` digitado errado não passa despercebido) e todos
os problemas são listados de uma vez ao iniciar.

### `settings`

| Campo | Padrão | Descrição |
|---|---|---|
| `poll_interval_seconds` | `5` | Camada rápida (2–3600 s). Também pode ser trocado na interface |
| `detail_interval_seconds` | `15` | Processos, portas e stats de contêineres |
| `inventory_interval_seconds` | `60` | Sistema, VPS, timers, cron, eventos |
| `security_interval_seconds` | `300` | Auditoria de segurança, fail2ban, logins, sudo e SMART |
| `updates_interval_seconds` | `1800` | Contagem de atualizações pendentes |
| `endpoint_interval_seconds` | `60` | Verificação dos `endpoints` (a partir do Windows) |
| `cert_warning_days` | `14` | Certificados que expiram em até N dias ficam em "Atenção" e geram alerta (uma vez por dia) |
| `latency_probe` | `"auto"` | `auto` (ICMP no Windows, senão SSH), `icmp`, `ssh` ou `off` |
| `command_timeout_seconds` | `5` | Timeout de cada comando SSH. **Máximo 5** |
| `connect_timeout_seconds` | `5` | Timeout de conexão/handshake/autenticação |
| `minimize_to_tray` | `true` | Fechar a janela mantém o monitor na bandeja |
| `start_minimized` | `false` | Inicia oculto na bandeja |
| `appearance_mode` | `"dark"` | `dark`, `light` ou `system` (tema ciano nos dois modos) |
| `log_lines` | `50` | Linhas iniciais no modal de logs |
| `process_limit` | `200` | Quantos processos (top por CPU) exibir |
| `known_hosts_file` | `%LOCALAPPDATA%\FirawynixMonitor\known_hosts` | Onde as chaves de host aceitas são gravadas |
| `notifications.enabled` | `true` | Liga/desliga os toasts |
| `notifications.notify_on_recovery` | `true` | Avisa quando algo se recupera |
| `notifications.notify_on_disconnect` | `true` | Avisa quando um servidor fica inacessível |
| `notifications.alert_on_stop` | `false` | Também alerta quando um item crítico **para** (sem falhar). Paradas feitas pelo próprio monitor não geram alerta |
| `notifications.security_alerts` | `true` | Alerta novas falhas **críticas** de segurança |
| `notifications.notify_on_ssh_login` | `"root"` | Logins SSH que geram alerta: `root`, `all` (qualquer usuário) ou `off`. As reconexões do próprio monitor são ignoradas |
| `notifications.cooldown_seconds` | `120` | Intervalo mínimo entre alertas iguais |
| `notifications.app_id` | — | AppUserModelID dos toasts (opcional) |
| `thresholds.cpu_percent` / `mem_percent` / `disk_percent` | `90` | Limites de alerta (0 desativa) |
| `thresholds.steal_percent` | `10` | CPU "roubada" pelo hipervisor — VPS com vizinhos barulhentos (0 desativa) |
| `thresholds.latency_ms` | `0` | Latência Windows → servidor (0 desativa) |
| `thresholds.sustain_polls` | `3` | Coletas seguidas acima do limite antes de alertar (disco alerta na hora). Só "normaliza" 5 pontos (10% na latência) abaixo do limite |
| `history.enabled` / `retention_days` / `file` | `true` / `7` / `%LOCALAPPDATA%\…\history.sqlite3` | Histórico dos gráficos (bancos antigos são migrados automaticamente) |
| `events.priority` | `"err"` | Prioridade máxima dos eventos do journal (`emerg`…`notice`) |
| `events.limit` / `events.since_hours` | `100` / `24` | Quantidade e janela dos eventos |
| `windows.event_log` | `true` | Alertas e ações no Visualizador de Eventos |
| `windows.flash_taskbar` | `true` | Pisca a barra de tarefas em alertas críticos |
| `windows.prevent_sleep` | `false` | Impede a suspensão do PC enquanto o monitor estiver aberto |
| `windows.accent_title_bar` | `true` | Barra de título com a cor do tema (Windows 11) |

As opções `windows.*` também podem ser trocadas no botão **Windows ⚙**; a escolha feita
na interface fica em `%APPDATA%\FirawynixMonitor\preferences.json` e tem prioridade.

### `servers[]`

| Campo | Padrão | Descrição |
|---|---|---|
| `name` | — | Nome exibido (único) |
| `host` / `port` | — / `22` | Endereço SSH |
| `username` | — | Usuário SSH (recomendado: usuário dedicado, ex. `monitor`) |
| `key_file` | — | Chave privada (`~` e `%VAR%` são expandidos). Sem ela, usa o agente SSH e as chaves padrão de `~/.ssh` |
| `key_passphrase_env` / `password_env` | — | **Nome** da variável de ambiente com a passphrase / senha |
| `key_passphrase_credential` / `password_credential` | — | `true` (nome padrão `FirawynixMonitor/<servidor>` ou `…/<servidor>/passphrase`) ou o nome de uma credencial genérica do **Gerenciador de Credenciais do Windows** |
| `allow_agent` / `look_for_keys` | `true` | Usa o agente (OpenSSH do Windows / Pageant) e as chaves padrão |
| `host_key_policy` | `"accept-new"` | `accept-new` (TOFU, como o OpenSSH) ou `strict`. Chave **diferente** da gravada é sempre recusada |
| `unit_types` | todos | Tipos de unidade systemd coletados: `service`, `timer`, `socket`, `mount`, `path` |
| `use_sudo` | `true` | `sudo -n` para iniciar/parar/reiniciar unidades (ignorado se `username` for `root`) |
| `docker` / `docker_sudo` | `"auto"` / `false` | `auto` (detecta), `on` (avisa se indisponível) ou `off`; sudo para o Docker |
| `podman` / `podman_sudo` | `"auto"` / `false` | Idem para o Podman (rootless funciona sem sudo) |
| `lxd` / `lxd_sudo` | `"auto"` / `false` | Instâncias LXD/Incus (`incus` ou `lxc`, inclusive snap) |
| `kubernetes` | `"auto"` | Pods via `kubectl` |
| `kubectl_command` | `"kubectl"` | Ex.: `"k3s kubectl"`, `"microk8s kubectl"` ou caminho absoluto |
| `kubectl_sudo` | `false` | Necessário no k3s (kubeconfig só legível pelo root) |
| `libvirt` / `libvirt_uri` / `libvirt_sudo` | `"auto"` / `"qemu:///system"` / `false` | VMs via `virsh` |
| `smart` / `smart_sudo` | `"auto"` / `false` | Saúde SMART dos discos (o `smartctl` exige root: habilite `smart_sudo`) |
| `security` | `true` | Auditoria de segurança (somente leitura) |
| `security_sudo` | `false` | `sudo -n` para `sshd -T`, `ufw status`, `iptables -S INPUT`, `nft list ruleset` e `fail2ban-client status` |
| `security_actions` | `false` | Banir/desbanir IPs no fail2ban pela interface (exige `security_sudo`) |
| `endpoints` | `[]` | Sites/APIs/portas verificados a partir do Windows: `https://…`, `http://…`, `tls://host:porta`, `tcp://host:porta` (credenciais na URL são recusadas) |
| `bandwidth_quota_gb` / `bandwidth_count` | — / `"tx"` | Franquia mensal do provedor (GB) e o que ela conta: `tx` (enviado, o comum em VPS) ou `total` |
| `logs_sudo` | `false` | `sudo -n` com o `journalctl` |
| `network_sudo` | `false` | `sudo -n ss -tulnp` para ver o processo dono de todas as portas |
| `process_actions` | `false` | Habilita encerrar processos (TERM/KILL) |
| `process_sudo` | `false` | `sudo -n kill` (**não recomendado**: permite encerrar qualquer processo) |
| `poll_interval_seconds` | global | Intervalo específico deste servidor |
| `critical_services` | `["*"]` | Padrões *glob* dos itens que geram alerta. `nginx` casa com `nginx.service`; prefixos restringem o tipo: `systemd:`, `docker:`, `podman:`, `lxd:` (ou `incus:`), `k8s:` (ex.: `k8s:prod/*`), `vm:` |
| `exclude_services` | `[]` | Padrões ocultados da tabela e dos alertas |

### Segredos

Senhas e passphrases **nunca** ficam no `servers.json` — chaves como `password`,
`passphrase` ou `sudo_password` são recusadas. Há duas formas seguras:

1. **Gerenciador de Credenciais do Windows** (recomendado no Windows): use
   `"password_credential": true` e grave a senha pelo botão **Windows ⚙ → Credenciais**,
   com o próprio Windows — `cmdkey /generic:FirawynixMonitor/<servidor> /user:<usuario> /pass`
   (pede a senha) — ou, rodando pelo código-fonte, `python main.py --set-credential <servidor>`. O
   segredo fica criptografado pelo Windows (DPAPI) para o seu usuário e nunca aparece em
   arquivo ou log.
2. **Variável de ambiente**: `"password_env": "NOME"` e o valor nas variáveis do Windows
   ou em um `.env` ao lado do `servers.json`/executável (veja [`.env.example`](.env.example)).

## Preparando os servidores Linux

1. **Usuário dedicado com chave:**

   ```bash
   sudo useradd -m -s /bin/bash monitor
   sudo -u monitor mkdir -m 700 -p ~monitor/.ssh
   # chave pública gerada no Windows com: ssh-keygen -t ed25519
   sudo -u monitor tee -a ~monitor/.ssh/authorized_keys < id_ed25519.pub
   sudo chmod 600 ~monitor/.ssh/authorized_keys
   ```

2. **Leitura sem sudo (preferível):**

   ```bash
   sudo usermod -aG systemd-journal monitor   # logs, eventos, logins SSH, sudo e OOM killer
   sudo usermod -aG libvirt monitor           # VMs (se houver)
   sudo usermod -aG docker monitor            # ATENÇÃO: grupo docker ≈ acesso root
   sudo apt install vnstat smartmontools      # opcional: franquia mensal e SMART
   ```

3. **Ações e leituras privilegiadas sem senha, apenas para os comandos necessários** — o
   monitor usa `sudo -n` (não interativo) e **nunca** envia senha ao sudo. Crie
   `/etc/sudoers.d/firawynix-monitor` com `sudo visudo -f /etc/sudoers.d/firawynix-monitor`
   a partir de [`docs/sudoers.example`](docs/sudoers.example), que lista o comando exato
   de cada opção (serviços, auditoria, fail2ban, SMART, LXD…). Exemplo mínimo:

   ```sudoers
   Cmnd_Alias FWX_NGINX = /usr/bin/systemctl --no-block start nginx.service, \
                          /usr/bin/systemctl --no-block stop nginx.service, \
                          /usr/bin/systemctl --no-block restart nginx.service
   monitor ALL=(root) NOPASSWD: FWX_NGINX
   ```

   Ações usam `--no-block` (systemd) e `-t 3` (contêineres) para caber no limite de 5 s;
   o que demorar mais aparece como **Iniciando** na coleta seguinte.

4. **CPU/memória por serviço** exigem cgroup v2 (Ubuntu 22.04+, Debian 11+, RHEL 9+);
   em cgroup v1 essas colunas ficam vazias e o resto funciona normalmente.

## Uso

* **Servidor**: *Visão geral* mostra todos; escolha um servidor para as abas. Um `●` ao
  lado do nome indica problema. Na visão geral, duplo clique em um servidor ou problema
  abre o item correspondente (endpoints abrem a aba VPS; segurança, a aba Segurança).
* **Tabelas**: clique nos cabeçalhos para ordenar; botão direito para ações, *Copiar
  linha* e *Exportar tabela (CSV)*. Duplo clique abre logs/detalhes.
* **Busca**: `Ctrl+F` na aba atual (`Esc` limpa). Vários termos são combinados com "E".
* **Segurança**: a nota soma as verificações (OK = 1, Atenção = ½, Crítico = 0; "Info" e
  "Indeterminado" não contam). Em *Tentativas SSH*, selecione um IP e **Banir** (vai para
  a jail `sshd` do fail2ban); em *Fail2ban*, **Desbanir**. O monitor nunca bane o próprio
  IP nem o loopback, e toda ação pede confirmação.
* **VPS**: *Verificar agora* refaz os endpoints; a franquia aparece quando
  `bandwidth_quota_gb` está definido e o vnStat está instalado.
* **Stacks**: selecione uma stack para ver os membros; as ações valem para todos os
  contêineres dela. Namespaces do Kubernetes são somente leitura aqui.
* **Pods**: *Reiniciar* exclui o pod para o controlador recriá-lo. Iniciar/Parar não se aplicam.
* **VMs**: *Parar* envia desligamento ACPI (`virsh shutdown`), nunca `destroy`.
* **Terminal SSH**: abre `ssh usuario@host` (com a chave configurada) no Windows
  Terminal ou em um console novo.
* **Windows ⚙**: liga/desliga as integrações com o Windows e grava credenciais.
* `F5` força uma coleta completa. O switch *Alertas* (e o menu da bandeja) silencia os toasts.
* **Bandeja**: fechar a janela mantém o monitor rodando. Verde = tudo OK, amarelo =
  avisos, vermelho = item crítico com falha, site fora do ar, disco falhando ou servidor
  inacessível, cinza = conectando. O menu também tem *Iniciar com o Windows*.
* **Logs da aplicação**: `%LOCALAPPDATA%\FirawynixMonitor\logs\monitor.log`.

## Integração com a API do Windows

Tudo via `ctypes` (sem dependências extras) e ignorado fora do Windows:

| Recurso | API | Detalhe |
|---|---|---|
| Credenciais | `CredWriteW` / `CredReadW` / `CredDeleteW` (advapi32) | Credencial genérica, compatível com `cmdkey` e com o painel *Gerenciador de Credenciais* |
| Visualizador de Eventos | `RegisterEventSourceW` / `ReportEventW` | Log *Aplicativo*, origem `FirawynixMonitor`; IDs 1001 (falha de serviço), 1002 (recuperado), 1003/1004 (conexão), 1005 (limite), 1006 (endpoint), 1007 (segurança), 1008 (SMART), 1009 (ação executada — trilha de auditoria), 1010 (franquia), 1011 (login SSH) |
| Barra de título | `DwmSetWindowAttribute` (dwmapi) | Modo escuro + legenda/borda/texto na cor do tema (Windows 11) |
| Barra de tarefas | `FlashWindowEx` (user32) | Pisca em alertas críticos até a janela receber foco |
| Iniciar com o Windows | Registro `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Sempre com `--minimized` e o caminho do `servers.json` |
| Energia | `SetThreadExecutionState` (kernel32) | Impede a suspensão enquanto o monitor estiver aberto |
| Ping | `IcmpSendEcho` (iphlpapi) | Latência sem privilégios de administrador |

Para mensagens completas no Visualizador de Eventos (sem o aviso "a descrição não foi
encontrada"), registre a origem uma vez, no PowerShell como administrador:

```powershell
New-EventLog -LogName Application -Source FirawynixMonitor
```

## Empacotamento (`.exe` com PyInstaller)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

O script cria `.venv`, instala `requirements-dev.txt`, roda os testes e gera
**`dist\FirawynixMonitor.exe`** (arquivo único, sem console, com ícone, versão e o tema
ciano embutido). Manualmente: `pip install -r requirements-dev.txt` e
`pyinstaller --noconfirm --clean FirawynixMonitor.spec`. Distribua o `.exe` com um
`servers.json` na mesma pasta.

**Iniciar junto com o Windows**: use o menu da bandeja ou **Windows ⚙ → Iniciar com o
Windows** (grava a chave `Run` do seu usuário; não precisa de administrador).

## Segurança

* **Sem agente**: nada é instalado nos servidores; somente comandos de leitura e as ações
  explicitamente confirmadas pelo usuário.
* **Sem segredos em texto plano**: `servers.json` só referencia variáveis de ambiente ou
  credenciais do Windows (DPAPI); URLs de endpoints com usuário/senha são recusadas.
* **Sem senha de sudo**: sempre `sudo -n`; libere o mínimo via sudoers (NOPASSWD).
* **Chaves de host verificadas**: TOFU (`accept-new`) ou `strict`; chave divergente é
  recusada com alerta de possível *man-in-the-middle*.
* **Sem injeção de comandos**: nomes de unidades, contêineres, instâncias, pods, VMs e
  jails passam por whitelist (nunca começam com `-`), IPs são normalizados com
  `ipaddress`, PIDs são validados (PID 1 nunca), `kubectl_command` e `libvirt_uri` são
  validados na configuração, e todo valor passa por `shlex.quote`; os comandos rodam via
  `sh -c` com `LC_ALL=C`.
* **Ações destrutivas desligadas por padrão**: encerrar processos exige
  `process_actions: true` e banir IPs exige `security_actions: true`; toda ação pede
  confirmação e fica registrada no log e no Visualizador de Eventos.
* **Nunca se tranca para fora**: o IP do próprio monitor (visto pelo servidor em
  `$SSH_CLIENT`) não pode ser banido; a latência não abre conexões extras no sshd.
* **Atualizações só pelo cache local**: nenhum comando do monitor baixa nada da internet.
* **Instância única** (mutex do Windows) e logs sem credenciais.

## Testes

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

Cobrem os parsers (formatos modernos e legados de `systemctl`, `docker`/`podman`,
`incus`/`lxc`, `kubectl`, `virsh`, `/proc/*`, `ss` e o fallback `/proc/net`, `free`,
`df`, cron, journal, `sshd_config` com `Include`/`Match`, `authorized_keys`, fail2ban,
`smartctl -j` ATA/NVMe, vnStat 1.x/2.x, `timedatectl` antigo e novo, DMI), a auditoria de
segurança (servidor endurecido × VPS exposto), os construtores de comando (tentativas de
injeção e sintaxe POSIX de cada comando composto), a validação da configuração, as
políticas de alerta, o histórico em SQLite (inclusive a migração), os endpoints contra
servidores HTTP/HTTPS locais com certificados gerados no teste (válido, expirando,
autoassinado), os layouts das estruturas da API do Windows e o loop do monitor (camadas,
reconexão, perda de conexão, timeouts, endpoints em segundo plano) com um cliente SSH falso.

## Solução de problemas

| Sintoma | Causa / solução |
|---|---|
| "O sudo exigiu senha" | O comando não está liberado com NOPASSWD. Confira o caminho (`command -v systemctl`) e o texto exato em `docs/sudoers.example` |
| "Interactive authentication required" | `use_sudo` desligado e o polkit negou. Ligue `use_sudo` e configure o sudoers |
| Logs/eventos incompletos, "Journal parcial", tentativas SSH "Indeterminado" | Adicione o usuário ao grupo `systemd-journal` (ou use `logs_sudo`) |
| "Sem permissão no socket do Docker/Podman" | Grupo `docker`, Podman rootless, ou `docker_sudo`/`podman_sudo` |
| "Sem permissão no LXD/Incus" | Grupo `incus-admin` (ou `lxd`) ou `lxd_sudo` |
| "kubectl sem kubeconfig" / sem permissão | No k3s use `"kubectl_command": "k3s kubectl"` com `kubectl_sudo: true` |
| "Sem permissão no libvirt" | `sudo usermod -aG libvirt monitor` ou `libvirt_sudo` |
| SMART "precisa de root" | `smart_sudo: true` + regra do sudoers. Em VPS os discos são virtuais e não têm SMART |
| Firewall "não detectado" | Sem `security_sudo` não dá para ler iptables/nftables; confira também o firewall do painel do provedor |
| Fail2ban vazio | `fail2ban-client` exige root: `security_sudo: true` + regra do sudoers |
| Franquia sem dados | Instale o `vnstat` no servidor (ele passa a contar a partir da instalação) |
| Latência "SSH" em vez de "ICMP" | O servidor/firewall bloqueia ping; a medida pelo SSH continua válida |
| Certificado "inválido" em site interno | A validação usa os certificados confiáveis do Windows: importe a CA interna no Windows |
| Portas sem processo | Processos de outros usuários exigem `network_sudo: true` |
| Colunas CPU/Memória vazias para serviços | O servidor usa cgroup v1 |
| "A chave SSH ... MUDOU" | Servidor reinstalado ou interceptação. Se legítimo, remova a linha do host em `%LOCALAPPDATA%\FirawynixMonitor\known_hosts` (e em `~/.ssh/known_hosts`) |
| Aviso "não respondeu a tempo" | Servidor sobrecarregado; os últimos dados continuam visíveis. Após 3 ciclos com timeout o monitor reconecta |
| Terminal SSH não abre | Instale o *Cliente OpenSSH* (Configurações > Aplicativos > Recursos opcionais); o comando é copiado para a área de transferência |
| Toasts não aparecem | Verifique *Configurações > Sistema > Notificações* e o *Não incomodar*. Para outro nome de aplicativo, defina `notifications.app_id` com um AppUserModelID registrado |
| Evento sem descrição no Visualizador | Registre a origem com `New-EventLog` (veja acima) |

## Atualizando dependências

As versões em `requirements*.txt` são exatas (incluindo as transitivas) para builds
reprodutíveis. A v3 não adicionou dependências: as integrações com o Windows usam só a
biblioteca padrão (`ctypes`, `winreg`) e os certificados são lidos com o `cryptography`
que o Paramiko já instala. Para atualizar:

```powershell
python -m venv .venv-upd; .\.venv-upd\Scripts\Activate.ps1
pip install customtkinter paramiko pystray Pillow win11toast plyer python-dotenv pytest pyinstaller
pip freeze   # atualize os pinos de requirements.txt / requirements-dev.txt
python -m pytest
```

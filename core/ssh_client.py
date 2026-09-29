"""Conexão SSH (Paramiko), execução com timeout rígido e operações de alto nível.

* :mod:`core.commands` monta os comandos (validação + quoting);
* :mod:`core.parsers` interpreta as saídas;
* este módulo cuida da conexão, do timeout de cada comando e de traduzir
  resultados/erros para os modelos de :mod:`core.models`.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import paramiko

from config.settings import MAX_COMMAND_TIMEOUT, ServerConfig
from core import commands as cmd
from core import containers as engines
from core import parsers
from core.models import (
    SYSTEMD_UNIT_TYPES,
    ActionOutcome,
    ActionResult,
    ContainerImage,
    CronEntry,
    Fail2banJail,
    HostMetrics,
    ImageUpdate,
    JournalEntry,
    NetworkInfo,
    ProcessInfo,
    RuntimeResult,
    RuntimeState,
    SecurityRaw,
    ServiceAction,
    ServiceInfo,
    ServiceKind,
    SmartReport,
    SshLoginReport,
    Stack,
    SudoEvent,
    SystemInfo,
    TimerInfo,
    UpdatesInfo,
    VpsInfo,
)

log = logging.getLogger(__name__)

#: Limite de saída lida por comando (proteção de memória).
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
#: Intervalo de keepalive SSH (detecta conexões mortas sem esperar o TCP).
KEEPALIVE_SECONDS = 15


# ---------------------------------------------------------------------------
# Exceções
# ---------------------------------------------------------------------------

class SSHError(Exception):
    """Erro base de comunicação SSH."""


class SSHConnectionError(SSHError):
    """Falha de rede/transporte: a conexão precisa ser refeita."""


class SSHAuthError(SSHConnectionError):
    """Credenciais recusadas (chave, agente ou senha)."""


class SSHHostKeyError(SSHConnectionError):
    """Chave do host desconhecida (modo strict) ou divergente (possível MITM)."""


class SSHCommandTimeout(SSHError):
    """O comando excedeu o timeout configurado (máximo de 5 s)."""


class SSHCommandError(SSHError):
    """O comando executou mas retornou erro."""

    def __init__(self, message: str, result: CommandResult | None = None):
        super().__init__(message)
        self.result = result


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration: float

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        """stdout + stderr (útil para exibir mensagens de erro)."""
        return "\n".join(part for part in (self.stdout.strip(), self.stderr.strip()) if part)


# ---------------------------------------------------------------------------
# Cliente
# ---------------------------------------------------------------------------

class SSHClient:
    """Conexão agentless com um servidor Linux.

    Thread-safety: ``connect``/``close`` são serializados por lock; comandos
    podem ser executados concorrentemente (cada um abre seu próprio canal no
    mesmo transporte SSH, que o Paramiko multiplexa com segurança).
    """

    def __init__(
        self,
        server: ServerConfig,
        *,
        command_timeout: float = MAX_COMMAND_TIMEOUT,
        connect_timeout: float = 5.0,
        known_hosts_file: Path | None = None,
    ) -> None:
        self.server = server
        self.command_timeout = min(float(command_timeout), MAX_COMMAND_TIMEOUT)
        self.connect_timeout = float(connect_timeout)
        self.known_hosts_file = known_hosts_file
        self._lock = threading.RLock()
        self._state_lock = threading.Lock()
        self._client: paramiko.SSHClient | None = None
        self._systemctl_json: bool | None = None
        self._cgroup_v2: bool | None = None
        self._metrics_state: parsers.MetricsState | None = None
        self._process_sample: parsers.ProcessSample | None = None
        self._cgroup_sample: parsers.CgroupSample | None = None
        self._lxd_sample: tuple[float, dict[str, int]] | None = None
        #: Menor tempo de abertura de canal desde a última leitura (≈ RTT da rede).
        self._rtt_min: float | None = None

    # -- conexão ----------------------------------------------------------

    @property
    def connected(self) -> bool:
        client = self._client
        transport = client.get_transport() if client is not None else None
        return bool(transport and transport.is_active() and transport.is_authenticated())

    def _sudo(self, enabled: bool) -> bool:
        return enabled and self.server.username != "root"

    def connect(self) -> None:
        with self._lock:
            self._close_locked()
            client = paramiko.SSHClient()
            # known_hosts do usuário (~/.ssh/known_hosts) é somente leitura.
            client.load_system_host_keys()
            if self.known_hosts_file is not None:
                self.known_hosts_file.parent.mkdir(parents=True, exist_ok=True)
                self.known_hosts_file.touch(exist_ok=True)
                client.load_host_keys(str(self.known_hosts_file))
            if self.server.host_key_policy == "strict":
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                # "accept-new" (TOFU): aceita e grava a chave na primeira conexão;
                # chave divergente depois disso é SEMPRE rejeitada (BadHostKeyException).
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            server = self.server
            try:
                client.connect(
                    hostname=server.host,
                    port=server.port,
                    username=server.username,
                    password=server.resolve_password(),
                    key_filename=str(server.key_file) if server.key_file else None,
                    passphrase=server.resolve_passphrase(),
                    timeout=self.connect_timeout,
                    banner_timeout=self.connect_timeout,
                    auth_timeout=self.connect_timeout,
                    channel_timeout=self.command_timeout,
                    allow_agent=server.allow_agent,
                    look_for_keys=server.look_for_keys,
                )
            except paramiko.BadHostKeyException as exc:
                client.close()
                raise SSHHostKeyError(
                    f"A chave SSH de {server.host} MUDOU (possível ataque man-in-the-middle). "
                    "Conexão recusada. Se a troca foi legítima, remova a entrada antiga do "
                    "known_hosts."
                ) from exc
            except paramiko.AuthenticationException as exc:
                client.close()
                raise SSHAuthError(f"Autenticação recusada para {server.address}: {exc}") from exc
            except paramiko.SSHException as exc:
                client.close()
                if "not found in known_hosts" in str(exc):
                    raise SSHHostKeyError(
                        f"Host {server.host} ausente do known_hosts (host_key_policy=strict). "
                        f"Conecte uma vez com 'ssh {server.username}@{server.host}' para registrá-lo."
                    ) from exc
                raise SSHConnectionError(f"Erro SSH com {server.host}: {exc}") from exc
            except (OSError, EOFError) as exc:  # TimeoutError é subclasse de OSError
                client.close()
                if isinstance(exc, TimeoutError):
                    reason = "tempo esgotado"
                elif isinstance(exc, paramiko.ssh_exception.NoValidConnectionsError):
                    reason = "conexão recusada (sshd parado, porta fechada ou firewall)"
                else:
                    reason = exc
                raise SSHConnectionError(f"Não foi possível conectar a {server.host}:{server.port}: {reason}") from exc

            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(KEEPALIVE_SECONDS)
            self._client = client
            with self._state_lock:
                self._metrics_state = None
                self._process_sample = None
                self._cgroup_sample = None
            log.info("[%s] conectado a %s", server.name, server.address)

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001 - fechamento best-effort
                log.debug("Erro ao fechar conexão", exc_info=True)
            self._client = None

    def _transport(self) -> paramiko.Transport:
        client = self._client
        transport = client.get_transport() if client is not None else None
        if transport is None or not transport.is_active():
            raise SSHConnectionError(f"Sem conexão ativa com {self.server.host}")
        return transport

    # -- execução ---------------------------------------------------------

    def run(self, command: str, timeout: float | None = None) -> CommandResult:
        """Executa ``command`` com timeout total (conexão do canal + execução + leitura).

        Nunca bloqueia mais que ``timeout`` (máx. 5 s): além do prazo no laço de
        leitura, um watchdog derruba o transporte se o servidor travar no meio
        do protocolo — o monitor então reconecta com backoff.
        """
        timeout = min(timeout or self.command_timeout, MAX_COMMAND_TIMEOUT)
        transport = self._transport()
        started = time.monotonic()
        deadline = started + timeout
        watchdog = threading.Timer(timeout + 1.0, self._abort_transport, args=(transport, command))
        watchdog.daemon = True
        watchdog.start()
        channel: paramiko.Channel | None = None
        try:
            try:
                opened = time.monotonic()
                channel = transport.open_session(timeout=timeout)
                self._record_rtt(time.monotonic() - opened)
                channel.exec_command(cmd.wrap_remote_command(command))
                channel.shutdown_write()  # EOF no stdin: nada fica esperando entrada
            except (paramiko.SSHException, OSError, EOFError) as exc:
                if time.monotonic() >= deadline:
                    raise SSHCommandTimeout(f"Timeout ({timeout:g}s) ao abrir canal: {command}") from exc
                raise SSHConnectionError(f"Falha ao abrir canal SSH: {exc}") from exc

            stdout, stderr = bytearray(), bytearray()
            while True:
                progressed = False
                while channel.recv_ready():
                    stdout += channel.recv(65536)
                    progressed = True
                while channel.recv_stderr_ready():
                    stderr += channel.recv_stderr(65536)
                    progressed = True
                if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
                    raise SSHCommandError(f"Saída excedeu {MAX_OUTPUT_BYTES} bytes: {command}")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if time.monotonic() >= deadline:
                    raise SSHCommandTimeout(f"Comando excedeu {timeout:g}s: {_short(command)}")
                if not transport.is_active():
                    raise SSHConnectionError("Conexão SSH perdida durante o comando")
                if not progressed:
                    time.sleep(0.01)
            exit_code = channel.recv_exit_status()
        finally:
            watchdog.cancel()
            if channel is not None:
                try:
                    channel.close()
                except Exception:  # noqa: BLE001
                    pass

        result = CommandResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            duration=time.monotonic() - started,
        )
        log.debug("[%s] %s → %s em %.2fs", self.server.name, _short(command), exit_code, result.duration)
        return result

    def _record_rtt(self, seconds: float) -> None:
        # CHANNEL_OPEN → CONFIRMATION: um ida-e-volta sem criar processo no servidor
        # (nenhum pacote extra, nenhuma linha no log do sshd).
        with self._state_lock:
            if self._rtt_min is None or seconds < self._rtt_min:
                self._rtt_min = seconds

    def take_rtt(self) -> float | None:
        """Latência (ms) medida nos canais abertos desde a chamada anterior."""
        with self._state_lock:
            value, self._rtt_min = self._rtt_min, None
        return None if value is None else value * 1000

    def _abort_transport(self, transport: paramiko.Transport, command: str) -> None:
        log.warning("[%s] watchdog: servidor não respondeu a %r; derrubando conexão",
                    self.server.name, _short(command))
        try:
            transport.close()
        except Exception:  # noqa: BLE001
            pass

    # -- systemd ----------------------------------------------------------

    def list_units(self) -> list[ServiceInfo]:
        types = self.server.unit_types or SYSTEMD_UNIT_TYPES
        if self._systemctl_json is not False:
            result = self.run(cmd.build_list_units_command(types, json_output=True))
            if result.ok and result.stdout.lstrip().startswith("["):
                try:
                    units = parsers.parse_systemctl_json(result.stdout)
                except ValueError:
                    log.info("[%s] JSON do systemctl inválido; usando saída tabular", self.server.name)
                else:
                    self._systemctl_json = True
                    return units
            elif not result.ok and not re.search(r"unrecognized|invalid|unknown|json", result.stderr, re.I):
                # systemd presente mas inoperante (ex.: "System has not been booted with systemd").
                raise SSHCommandError(f"systemctl indisponível: {result.output or result.exit_code}", result)
            # systemd antigo: ignora ou rejeita --output=json em list-units.
            log.info("[%s] systemctl sem suporte a JSON; usando saída tabular", self.server.name)
            self._systemctl_json = False
        result = self.run(cmd.build_list_units_command(types, json_output=False))
        if not result.ok:
            raise SSHCommandError(f"systemctl indisponível: {result.output or result.exit_code}", result)
        return parsers.parse_systemctl_table(result.stdout)

    def service_resources(self) -> dict[str, tuple[float | None, int | None]]:
        """CPU/memória por serviço via cgroup v2 (vazio em cgroup v1)."""
        if self._cgroup_v2 is False:
            return {}
        result = self.run(cmd.CGROUP_SERVICES_CMD)
        with self._state_lock:
            resources, self._cgroup_sample = parsers.parse_cgroup_services(result.stdout, self._cgroup_sample)
        if self._cgroup_v2 is None:
            self._cgroup_v2 = bool(resources)
            if not resources:
                log.info("[%s] cgroup v2 indisponível: sem CPU/memória por serviço", self.server.name)
        return resources

    def timers(self) -> list[TimerInfo]:
        return parsers.parse_timers(self.run(cmd.TIMERS_CMD).stdout)

    # -- runtimes -----------------------------------------------------------

    def list_containers(self, runtime: ServiceKind) -> RuntimeResult:
        """Contêineres de qualquer motor OCI (Docker, Podman, containerd/nerdctl, CRI)."""
        mode, use_sudo, namespace = self._runtime_config(runtime)
        if mode == "off":
            return RuntimeResult(runtime, RuntimeState.DISABLED)
        if runtime is ServiceKind.CRI:
            command = engines.build_cri_ps_command(use_sudo)
        else:
            command = cmd.build_container_ps_command(runtime.value, use_sudo, namespace)
        result = self.run(command)
        if not result.ok:
            return _runtime_error(runtime, result)
        parse: Callable[[str], list[ServiceInfo]] = {
            ServiceKind.PODMAN: parsers.parse_podman_ps,
            ServiceKind.CRI: engines.parse_crictl_ps,
            ServiceKind.NERDCTL: lambda text: parsers.parse_docker_ps(text, ServiceKind.NERDCTL),
        }.get(runtime, parsers.parse_docker_ps)
        try:
            return RuntimeResult(runtime, RuntimeState.OK, tuple(parse(result.stdout)))
        except ValueError as exc:
            return RuntimeResult(runtime, RuntimeState.ERROR, (), f"Saída inesperada do {runtime.label}: {exc}")

    def container_stats(self, runtime: ServiceKind) -> dict[str, tuple[float | None, int | None]]:
        _mode, use_sudo, namespace = self._runtime_config(runtime)
        if not runtime.manageable:
            return {}
        result = self.run(cmd.build_container_stats_command(runtime.value, use_sudo, namespace))
        # Aproveita a saída mesmo com código ≠ 0 (um contêiner pode sumir no meio da coleta).
        return parsers.parse_container_stats(result.stdout)

    def list_pods(self) -> RuntimeResult:
        kind = ServiceKind.KUBERNETES
        if self.server.kubernetes == "off":
            return RuntimeResult(kind, RuntimeState.DISABLED)
        result = self.run(cmd.build_pods_command(self.server.kubectl_command, self._sudo(self.server.kubectl_sudo)))
        if not result.ok:
            return _runtime_error(kind, result)
        return RuntimeResult(kind, RuntimeState.OK, tuple(parsers.parse_pods(result.stdout)))

    def list_vms(self) -> RuntimeResult:
        kind = ServiceKind.LIBVIRT
        if self.server.libvirt == "off":
            return RuntimeResult(kind, RuntimeState.DISABLED)
        result = self.run(cmd.build_vm_list_command(self.server.libvirt_uri, self._sudo(self.server.libvirt_sudo)))
        if not result.ok:
            return _runtime_error(kind, result)
        return RuntimeResult(kind, RuntimeState.OK, tuple(parsers.parse_virsh_list(result.stdout)))

    def list_lxd(self) -> RuntimeResult:
        kind = ServiceKind.LXD
        if self.server.lxd == "off":
            return RuntimeResult(kind, RuntimeState.DISABLED)
        result = self.run(cmd.build_lxd_list_command(self._sudo(self.server.lxd_sudo)))
        if not result.ok:
            return _runtime_error(kind, result)
        try:
            _cli, instances, usage = parsers.parse_lxd_list(result.stdout)
        except ValueError as exc:
            return RuntimeResult(kind, RuntimeState.ERROR, (), f"Saída inesperada do LXD/Incus: {exc}")
        now = time.monotonic()
        with self._state_lock:
            previous, self._lxd_sample = self._lxd_sample, (now, usage)
        if previous is not None and now > previous[0]:
            elapsed_ns = (now - previous[0]) * 1e9
            instances = [
                dataclasses.replace(item, cpu_percent=max(0.0, 100.0 * (usage[item.name] - previous[1][item.name])
                                                          / elapsed_ns))
                if item.name in usage and item.name in previous[1] else item
                for item in instances
            ]
        return RuntimeResult(kind, RuntimeState.OK, tuple(instances))

    def _runtime_config(self, runtime: ServiceKind) -> tuple[str, bool, str]:
        """(modo, sudo, namespace) do motor de contêiner."""
        engine_id = engines.ENGINE_OF_KIND[runtime]
        namespace = self.server.nerdctl_namespace if runtime is ServiceKind.NERDCTL else ""
        return engines.engine_mode(self.server, engine_id), engines.engine_sudo(self.server, engine_id), namespace

    # -- motores de contêiner: detecção, inventário, ações ------------------

    def discover_engines(self) -> engines.Discovery:
        return engines.parse_discovery(self.run(engines.DISCOVERY_CMD).stdout)

    def engine_inventory(self, engine_id: str) -> engines.EngineData:
        kind = engines.ENGINES[engine_id].kind
        _mode, use_sudo, namespace = self._runtime_config(kind)
        output = self.run(engines.build_engine_inventory_command(engine_id, use_sudo, namespace)).stdout
        return engines.parse_engine_inventory(engine_id, output)

    def buildah_inventory(self) -> tuple:
        output = self.run(engines.build_buildah_command(engines.engine_sudo(self.server, "buildah"))).stdout
        return engines.parse_buildah(output)

    def _admin_guard(self, op: str) -> ActionResult | None:
        if op in engines.DESTRUCTIVE_OPS and not self.server.container_admin:
            return ActionResult(ActionOutcome.ERROR, "Remoções pelo painel estão desativadas (container_admin).")
        return None

    def container_op(self, service: ServiceInfo, op: str) -> ActionResult:
        """pause / unpause / rm — o mesmo para Docker, Podman e containerd."""
        if not service.kind.manageable:
            return ActionResult(ActionOutcome.ERROR, f"{service.kind.label}: somente leitura.")
        blocked = self._admin_guard(op)
        if blocked is not None:
            return blocked
        _mode, use_sudo, namespace = self._runtime_config(service.kind)
        label = {"pause": "Pausar", "unpause": "Retomar", "rm": "Remover"}.get(op, op)
        return self._run_action(engines.build_container_op_command(service, op, use_sudo, namespace), label,
                                service.name)

    def inspect_container(self, service: ServiceInfo) -> str:
        _mode, use_sudo, namespace = self._runtime_config(service.kind)
        return _pretty_json(self._text_output(engines.build_container_op_command(service, "inspect", use_sudo,
                                                                                 namespace)))

    def image_op(self, engine_id: str, image: ContainerImage | None, op: str) -> ActionResult:
        blocked = self._admin_guard(op)
        if blocked is not None:
            return blocked
        _mode, use_sudo, namespace = self._runtime_config(engines.ENGINES[engine_id].kind)
        command = engines.build_image_op_command(engine_id, image, op, use_sudo, namespace)
        label = {"rmi": "Remover imagem", "prune": "Limpar imagens órfãs"}.get(op, op)
        return self._run_action(command, label, image.reference if image else engines.ENGINES[engine_id].label)

    def inspect_image(self, engine_id: str, image: ContainerImage) -> str:
        _mode, use_sudo, namespace = self._runtime_config(engines.ENGINES[engine_id].kind)
        return _pretty_json(self._text_output(engines.build_image_op_command(engine_id, image, "inspect", use_sudo,
                                                                             namespace)))

    def volume_op(self, engine_id: str, name: str, op: str) -> ActionResult:
        blocked = self._admin_guard(op)
        if blocked is not None:
            return blocked
        _mode, use_sudo, namespace = self._runtime_config(engines.ENGINES[engine_id].kind)
        return self._run_action(engines.build_volume_op_command(engine_id, name, op, use_sudo, namespace),
                                "Remover volume", name)

    def inspect_volume(self, engine_id: str, name: str) -> str:
        _mode, use_sudo, namespace = self._runtime_config(engines.ENGINES[engine_id].kind)
        return _pretty_json(self._text_output(engines.build_volume_op_command(engine_id, name, "inspect", use_sudo,
                                                                              namespace)))

    def check_image_update(self, image: ContainerImage) -> ImageUpdate:
        """Compara o digest local com o do registro via skopeo (não baixa a imagem)."""
        if not engines.updatable(image):
            return ImageUpdate(image.reference, "ignorada", detail="imagem local, órfã ou sem digest de registro")
        try:
            result = self.run(engines.build_image_update_command(image.reference))
        except SSHCommandTimeout:
            return ImageUpdate(image.reference, "erro", detail="o registro não respondeu a tempo")
        if result.exit_code == 127 or "command not found" in result.output:
            return ImageUpdate(image.reference, "erro", detail="skopeo não instalado no servidor")
        return engines.parse_image_update(image.reference, result.stdout, image.digests)

    def console_command(self, service: ServiceInfo) -> str:
        _mode, use_sudo, namespace = self._runtime_config(service.kind)
        return engines.build_console_command(service, use_sudo, namespace)

    # -- host ---------------------------------------------------------------

    def host_metrics(self) -> HostMetrics:
        with self._state_lock:
            first = self._metrics_state is None or self._metrics_state.cpu is None
        result = self.run(cmd.build_metrics_command(sample_cpu_twice=first))
        with self._state_lock:
            metrics, self._metrics_state = parsers.parse_metrics(result.stdout, self._metrics_state)
        return metrics

    def processes(self) -> list[ProcessInfo]:
        with self._state_lock:
            first = self._process_sample is None
        result = self.run(cmd.build_processes_command(sample_twice=first))
        with self._state_lock:
            processes, self._process_sample = parsers.parse_processes(result.stdout, self._process_sample)
        return processes

    def network(self) -> NetworkInfo:
        result = self.run(cmd.build_ports_command(self._sudo(self.server.network_sudo)))
        return parsers.parse_ports(result.stdout)

    def cron(self) -> list[CronEntry]:
        return parsers.parse_cron(self.run(cmd.CRON_CMD).stdout, self.server.username)

    def journal_events(self, priority: str, limit: int, since_hours: int) -> list[JournalEntry]:
        return parsers.parse_journal_json(self.run(cmd.build_events_command(priority, limit, since_hours)).stdout)

    def system_info(self) -> tuple[SystemInfo, dict[str, float]]:
        return parsers.parse_system_info(self.run(cmd.SYSTEM_INFO_CMD).stdout)

    def vps_info(self) -> VpsInfo:
        return parsers.parse_vps(self.run(cmd.VPS_CMD).stdout)

    def smart(self) -> SmartReport:
        result = self.run(cmd.build_smart_command(self._sudo(self.server.smart_sudo)))
        if result.exit_code == 127 or "command not found" in result.stderr:
            return SmartReport(RuntimeState.NOT_INSTALLED, (), "smartctl não instalado (pacote smartmontools).")
        return parsers.parse_smart(result.stdout)

    def security_raw(self) -> SecurityRaw:
        server = self.server
        command = cmd.build_security_command(self._sudo(server.security_sudo),
                                             privileged=server.security_sudo or server.username == "root")
        return parsers.parse_security(self.run(command).stdout)

    def fail2ban_status(self) -> tuple[tuple[Fail2banJail, ...], str]:
        """Jails e IPs banidos (``fail2ban-client`` exige root: security_sudo)."""
        result = self.run(cmd.build_fail2ban_status_command(self._sudo(self.server.security_sudo)))
        if not result.ok:
            hint = parsers.describe_sudo_failure(result.output)
            first = result.output.strip().splitlines()[0] if result.output.strip() else f"código {result.exit_code}"
            return (), hint or first[:200]
        return parsers.parse_fail2ban(result.stdout), ""

    def ssh_logins(self) -> SshLoginReport:
        return parsers.parse_ssh_logins(self.run(cmd.SSH_LOGINS_CMD).stdout)

    def sudo_log(self) -> tuple[SudoEvent, ...]:
        return parsers.parse_sudo_log(self.run(cmd.build_sudo_log_command(self.server.username)).stdout)

    def updates(self) -> UpdatesInfo | None:
        return parsers.parse_updates(self.run(cmd.UPDATES_CMD).stdout)

    # -- ações --------------------------------------------------------------

    def service_action(self, service: ServiceInfo, action: ServiceAction) -> ActionResult:
        if not service.supports(action):
            return ActionResult(ActionOutcome.ERROR, f"'{action.label}' não se aplica a {service.type_label}.")
        server = self.server
        if service.kind is ServiceKind.SYSTEMD:
            command = cmd.build_unit_action_command(service.name, action, self._sudo(server.use_sudo))
        elif service.kind.manageable:
            _mode, use_sudo, namespace = self._runtime_config(service.kind)
            command = cmd.build_container_action_command(service.kind.value, [service.name], action, use_sudo,
                                                         namespace)
        elif service.kind is ServiceKind.KUBERNETES:
            command = cmd.build_pod_restart_command(server.kubectl_command, service.name,
                                                    self._sudo(server.kubectl_sudo))
        elif service.kind is ServiceKind.LXD:
            command = cmd.build_lxd_action_command(service.meta_value("cli", "lxc"), service.name, action,
                                                   self._sudo(server.lxd_sudo))
        else:
            command = cmd.build_vm_action_command(server.libvirt_uri, service.name, action,
                                                  self._sudo(server.libvirt_sudo))
        return self._run_action(command, action.label, service.name)

    def stack_action(self, stack: Stack, action: ServiceAction) -> ActionResult:
        if not stack.kind.manageable:
            return ActionResult(ActionOutcome.ERROR, "Ações em lote só existem para stacks de contêineres.")
        _mode, use_sudo, namespace = self._runtime_config(stack.kind)
        names = [member.name for member in stack.members]
        command = cmd.build_container_action_command(stack.kind.value, names, action, use_sudo, namespace)
        return self._run_action(command, action.label, f"stack {stack.name} ({len(names)} contêineres)")

    def kill_process(self, pid: int, force: bool) -> ActionResult:
        if not self.server.process_actions:
            return ActionResult(ActionOutcome.ERROR, "Ações em processos estão desativadas (process_actions).")
        command = cmd.build_kill_command(pid, force, self._sudo(self.server.process_sudo))
        return self._run_action(command, "Forçar encerramento" if force else "Encerrar", f"PID {pid}")

    def fail2ban_action(self, jail: str, ip: str, ban: bool) -> ActionResult:
        if not self.server.security_actions:
            return ActionResult(ActionOutcome.ERROR, "Ações no fail2ban estão desativadas (security_actions).")
        command = cmd.build_fail2ban_ban_command(jail, ip, ban, self._sudo(self.server.security_sudo))
        return self._run_action(command, "Banir" if ban else "Desbanir", f"{ip} (jail {jail})")

    def _run_action(self, command: str, label: str, target: str) -> ActionResult:
        try:
            result = self.run(command)
        except SSHCommandTimeout:
            return ActionResult(ActionOutcome.PENDING,
                                f"'{label}' em {target} ainda em andamento após {self.command_timeout:g}s; "
                                "acompanhe o status na tabela.")
        if result.ok:
            return ActionResult(ActionOutcome.OK, f"{label}: {target} — solicitado com sucesso.")
        hint = parsers.describe_sudo_failure(result.output)
        detail = hint or result.output or f"código de saída {result.exit_code}"
        return ActionResult(ActionOutcome.ERROR, f"Falha em '{label}' ({target}): {detail}")

    # -- logs / detalhes ----------------------------------------------------

    def logs_command(self, service: ServiceInfo, lines: int) -> str:
        server = self.server
        if service.kind is ServiceKind.SYSTEMD:
            return cmd.build_journal_command(service.name, lines, self._sudo(server.logs_sudo))
        if service.kind is ServiceKind.CRI:
            _mode, use_sudo, _ns = self._runtime_config(service.kind)
            return cmd.build_cri_logs_command(service.meta_value("id"), lines, use_sudo)
        if service.kind.is_container:
            _mode, use_sudo, namespace = self._runtime_config(service.kind)
            return cmd.build_container_logs_command(service.kind.value, service.name, lines, use_sudo, namespace)
        if service.kind is ServiceKind.KUBERNETES:
            return cmd.build_pod_logs_command(server.kubectl_command, service.name, lines,
                                              self._sudo(server.kubectl_sudo))
        if service.kind is ServiceKind.LXD:
            return cmd.build_lxd_info_command(service.meta_value("cli", "lxc"), service.name,
                                              self._sudo(server.lxd_sudo))
        return cmd.build_vm_info_command(server.libvirt_uri, service.name, self._sudo(server.libvirt_sudo))

    def service_logs(self, service: ServiceInfo, lines: int) -> str:
        return self._text_output(self.logs_command(service, lines))

    def stack_logs(self, stack: Stack, lines: int) -> str:
        if not stack.kind.manageable:
            return "\n\n".join(f"===== {m.name} =====\n{self.service_logs(m, lines)}" for m in stack.members[:10])
        _mode, use_sudo, namespace = self._runtime_config(stack.kind)
        per_container = max(10, lines // max(1, len(stack.members)))
        command = cmd.build_stack_logs_command(stack.kind.value, [m.name for m in stack.members],
                                               per_container, use_sudo, namespace)
        return self._text_output(command)

    def _text_output(self, command: str) -> str:
        result = self.run(command)
        text = parsers.strip_ansi(result.output).rstrip()
        if not result.ok:
            hint = parsers.describe_sudo_failure(result.output)
            prefix = f"[código de saída {result.exit_code}]"
            return f"{prefix} {hint}\n\n{text}" if hint else f"{prefix}\n{text}"
        return text or "(sem entradas de log)"


def _runtime_error(kind: ServiceKind, result: CommandResult) -> RuntimeResult:
    """Falha de um runtime → estado + dica (a mensagem vai em ``message``, não em ``items``)."""
    state, message = parsers.classify_runtime_error(kind, result.exit_code, result.output)
    return RuntimeResult(kind, state, (), message)

def _pretty_json(text: str) -> str:
    """Saídas de ``inspect`` (JSON) indentadas para leitura; outros textos intactos."""
    stripped = text.strip()
    if stripped.startswith(("[", "{")):
        try:
            return json.dumps(json.loads(stripped), indent=2, ensure_ascii=False)
        except ValueError:
            pass
    return text


def _short(command: str, limit: int = 120) -> str:
    return command if len(command) <= limit else command[: limit - 1] + "…"

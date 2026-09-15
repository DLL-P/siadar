# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/).

## [0.1.0] — 2026-09-15

### Adicionado

- **M1 — Captura**: agrega pacotes em flows por janela de tempo, direto da interface de rede
  (`scapy`).
- **M2 — Triagem**: classificação de tráfego (normal vs. 9 famílias de ataque) via Random
  Forest.
- **M3 — Anomalia**: detecção de comportamento fora do padrão via Isolation Forest, incluindo
  score contínuo (`decision_function`).
- **M4 — Quarentena**: isolamento automático de IP suspeito via `iptables`, com TTL, lista de
  exclusão e persistência de estado. Roda em dry-run por padrão.
- **M5 — Resposta**: motor de decisão que combina classificação (M2) e severidade da anomalia
  (M3) para escolher entre log / alerta / quarentena (aciona M4).
- Persistência em CSV e SQL (SQLAlchemy) em paralelo.
- Suíte de testes (`pytest`) cobrindo os 5 módulos.
- Empacotamento (`pyproject.toml`), lint/formatação (`ruff`, `black`) e CI (GitHub Actions).

### Observação

Todos os 5 módulos estão implementados; a quarentena (M4) permanece em modo dry-run por padrão
até ser explicitamente habilitada (`--enforce-quarantine`).

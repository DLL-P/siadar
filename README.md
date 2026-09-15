# SIADAR

**Sistema Inteligente de Análise, Detecção de Anomalias e Resposta**

[![CI](https://github.com/DLL-P/siadar/actions/workflows/ci.yml/badge.svg)](https://github.com/DLL-P/siadar/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

Projeto pessoal de detecção de intrusão em redes corporativas com machine learning — captura
contínua, classificação, detecção de anomalia, quarentena e resposta automatizada, sobre uma
pilha 100% open-source.

> **Nota:** este é um projeto pessoal aberto e educacional — uma reescrita menor, do zero,
> focada em deixar o pipeline inteiro (captura → triagem → anomalia → quarentena → resposta)
> simples de ler, testar e estender. Existe também uma versão de pesquisa mais completa e
> privada, validada sobre o dataset público CICIDS2017 (2,8M flows reais) — este repositório
> não é ela, é um projeto independente com objetivo diferente: código aberto, simples de rodar
> e de contribuir.

## Índice

- [Pipeline](#pipeline)
- [Instalação](#instalação)
- [Uso](#uso)
- [Estrutura do projeto](#estrutura-do-projeto)
- [O achado que validou o método](#o-achado-que-validou-o-método)
- [Roadmap](#roadmap)
- [Contribuindo](#contribuindo)
- [Licença](#licença)

## Pipeline

| # | Módulo | O que faz |
|---|--------|-----------|
| M1 | **Captura** (`siadar.capture.live`) | Agrega pacotes em flows por janela de tempo, direto da interface de rede (`scapy`). |
| M2 | **Triagem** (`siadar.triage.classifier`) | Random Forest — classifica o tráfego entre normal (`BENIGN`) e 9 famílias de ataque conhecidas. |
| M3 | **Anomalia** (`siadar.anomaly.detector`) | Isolation Forest — sinaliza comportamento fora do padrão mesmo sem rótulo prévio; expõe um score contínuo. |
| M4 | **Quarentena** (`siadar.quarantine`) | Isola automaticamente um host/IP suspeito via `iptables`, com TTL e persistência. **Roda em dry-run por padrão.** |
| M5 | **Resposta** (`siadar.response`) | Combina a classificação (M2) com a severidade da anomalia (M3) para decidir entre log / alerta / quarentena. |

Status: **5 de 5 módulos implementados.**

## Instalação

```bash
git clone https://github.com/DLL-P/siadar.git
cd siadar
pip install -r requirements.txt

# opcional, para desenvolvimento (testes, lint, formatação)
pip install -e ".[dev]"
```

## Uso

```bash
# captura ao vivo numa interface, em modo seguro (quarentena em dry-run)
python -m siadar.capture.live --interface eth0 --window 60

# habilita bloqueio de firewall de verdade (decisão consciente, não é o padrão)
python -m siadar.capture.live --interface eth0 --window 60 --enforce-quarantine
```

Saída (exemplo):

```
[janela 1] 40 flows
  IP.ATACANTE -> IP.ALVO  |  PortScan  |  anômalo: sim
[resposta] QUARENTENA IP.ATACANTE  |  score de anomalia -0.210 abaixo do limiar de quarentena
[janela 2] 12 flows
  IP.QUALQUER -> IP.ALVO  |  BENIGN  |  anômalo: não
```

Cada flow classificado é gravado em CSV e em SQLite/SQL (`siadar.storage.db`), em paralelo.

## Estrutura do projeto

```
siadar/
├── siadar/
│   ├── capture/       # M1 — captura ao vivo e agregação em flows
│   ├── triage/         # M2 — classificação (Random Forest)
│   ├── anomaly/         # M3 — detecção de anomalia (Isolation Forest)
│   ├── quarantine/      # M4 — isolamento automático de host suspeito
│   ├── response/        # M5 — motor de decisão (log / alerta / quarentena)
│   ├── storage/          # persistência (CSV + SQL)
│   └── logging_config.py
├── tests/               # suíte pytest (14 testes)
├── data/                 # dados locais — inteiramente gitignored
├── .github/workflows/    # CI (GitHub Actions)
├── CLAUDE.md             # contexto do projeto para assistentes de IA
├── CONTRIBUTING.md
└── CHANGELOG.md
```

## O achado que validou o método

Um modelo treinado só com dados sintéticos "de mentirinha" pode acertar o próprio teste e ainda
assim falhar no mundo real. Ao rodar a captura ao vivo de verdade, ficou claro que o simulador de
treino nunca reproduzia a reação de um alvo real a uma porta fechada (ex.: um RST) — um gap
invisível até testar contra tráfego genuíno, não só contra o dataset de treino. Documentar isso é
tratado como parte da engenharia, tanto quanto o modelo em si.

## Roadmap

- [ ] Treinar e versionar modelos de referência (sintéticos/anonimizados) para rodar o projeto
      "out of the box", sem precisar treinar do zero.
- [ ] Ajustar a política de resposta (M5) com base em feedback de uso real.
- [ ] Suporte a outros backends de quarentena além de `iptables` (ex.: nftables, cloud firewalls).
- [ ] Dashboard simples para visualizar os flows classificados.

## Contribuindo

Contribuições, ideias e feedback são muito bem-vindos — o projeto ainda está em construção. Veja
o [`CONTRIBUTING.md`](CONTRIBUTING.md) para como rodar o projeto localmente e as convenções do
código.

## Licença

[MIT](LICENSE) — use, modifique e distribua livremente.

---

Stack: Python · scapy · scikit-learn · SQLAlchemy

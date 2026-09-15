# SIADAR — Sistema Inteligente de Análise, Detecção de Anomalias e Resposta

## O que é

Projeto pessoal do Rafael (não relacionado ao trabalho) de detecção de intrusão em redes
corporativas usando machine learning. Pipeline: captura de tráfego ao vivo → triagem/classificação
→ detecção de anomalias → quarentena e resposta automatizada.

**Importante — este NÃO é o mesmo repositório que `DLL-P/S.I.A.D.A.R`** no GitHub do Rafael.
Aquele é um projeto de pesquisa privado/proprietário, mais completo, validado no CICIDS2017 real,
com roadmap próprio (M4 = Perfil/UEBA, M5 = Previsão). Este repositório (`siadar`, público, MIT) é
uma reescrita menor e independente, com foco em ser simples de rodar e de contribuir — os módulos
M4/M5 aqui são Quarentena e Resposta, um roadmap diferente do repositório privado. Não confundir
os dois nem misturar conteúdo de um no outro sem confirmar com o Rafael.

## Stack

Python, scapy (captura de pacotes), scikit-learn (Random Forest + Isolation Forest),
SQLAlchemy (persistência), pandas.

## Status dos módulos (5/5 implementados — M4 e M5 ainda em modo conservador)

- [x] **M1 — Captura** — `siadar/capture/live.py` — agrega pacotes em flows por janela de
      tempo, direto da interface de rede.
- [x] **M2 — Triagem** — `siadar/triage/classifier.py` — Random Forest, classifica entre
      tráfego normal (BENIGN) e 9 famílias de ataque conhecidas.
- [x] **M3 — Anomalia** — `siadar/anomaly/detector.py` — Isolation Forest; `score()` expõe o
      valor contínuo de `decision_function` (negativo = mais anômalo), usado pelo M5 para
      graduar a resposta em vez de reagir a um sinal binário.
- [x] **M4 — Quarentena** — `siadar/quarantine/quarantine.py` — `QuarantineManager` isola um
      IP via `iptables`, com TTL, lista de exclusão (`NEVER_QUARANTINE`) e persistência em
      `data/quarantine_state.json`. **Roda em dry-run por padrão** (`enforce=False`) — só
      loga o que faria. Passar `--enforce-quarantine` (CLI) ou `enforce=True` é uma decisão
      consciente, não o padrão.
- [x] **M5 — Resposta** — `siadar/response/ml_response.py` — `ResponseEngine` combina o
      rótulo do M2 com o score contínuo do M3 para decidir entre `LOG` / `ALERT` /
      `QUARANTINE` (aciona o M4 nesse último caso). Política por thresholds em
      `QUARANTINE_SCORE_THRESHOLD` / `ALERT_SCORE_THRESHOLD` / `HIGH_SEVERITY_FAMILIES`.

O M1 (`run_capture`) já invoca o M5 automaticamente sempre que um flow sai do padrão
(anômalo ou rótulo diferente de `BENIGN`).

## Achado importante (documentar sempre que relevante — inclusive em posts/README)

Um modelo treinado só com dados sintéticos pode acertar 100% no próprio teste e ainda assim
falhar contra tráfego real. Ao rodar captura ao vivo de verdade, ficou claro que o simulador de
treino nunca reproduzia a reação de um alvo real a uma porta fechada (um RST simples) — um gap
invisível até testar contra tráfego genuíno, não só contra o dataset sintético. Documentar esse
tipo de gap é tratado como parte da engenharia, tanto quanto o modelo em si.

## Antes de publicar no GitHub (privacidade — importante)

Rafael administra infraestrutura de TI corporativa no trabalho (rede de terceiros, não deste
projeto). Ao preparar este repositório para ficar público, **nunca commitar**:

- IPs, hostnames ou topologia de rede reais (do trabalho ou pessoais);
- Credenciais, strings de conexão, chaves de API — usar `.env` (já no `.gitignore`,
  ver `.env.example`);
- PCAPs, CSVs ou bancos com capturas reais — `data/` está inteiramente no `.gitignore`;
  só exemplos sintéticos/anonimizados podem ser versionados, e isso deve ser uma decisão
  explícita, não automática;
- Qualquer dado que identifique a empresa ou a rede dela.

Revisar `git diff` (e o histórico, se houver) antes do primeiro push público.

## Convenções

- Docstrings e comentários em português (mesma língua do resto do projeto).
- Rodar módulos como `python -m siadar.<modulo>.<arquivo>`
  (ex.: `python -m siadar.capture.live --interface eth0 --window 60`).
- Modelos treinados (`.joblib`) não são versionados — ver `.gitignore`.
- `data/quarantine_state.json` (estado da quarentena) também está no `.gitignore` — nunca
  publicar o histórico de IPs bloqueados.

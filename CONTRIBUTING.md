# Contribuindo com o SIADAR

Antes de mais nada: valeu o interesse! Esse é um projeto pessoal, ainda em construção, e
feedback, ideias e contribuições são muito bem-vindos — não precisa ser nada grande.

## Formas de ajudar

- **Testar e reportar bugs.** Rodou e algo quebrou, ou o resultado não fez sentido? Abra uma
  issue descrevendo o que rodou e o que esperava ver.
- **Sugerir melhorias.** Principalmente nos módulos mais novos e conservadores por design —
  quarentena (M4) e resposta (M5) — feedback sobre a política de decisão (thresholds, famílias
  de alta severidade) é super bem-vindo.
- **Contribuir com código.** PRs pequenos e focados são mais fáceis de revisar que um PR
  gigante mexendo em tudo.
- **Melhorar a documentação.** Achou algo confuso no README ou nos docstrings? Manda a correção.

## Como rodar o projeto localmente

```bash
git clone <URL_DO_REPOSITORIO>
cd siadar
pip install -r requirements.txt
pip install -e ".[dev]"   # ferramentas de desenvolvimento (pytest, ruff, black)
```

## Antes de abrir um PR

```bash
pytest              # os testes precisam passar
ruff check .         # lint
black --check .      # formatação
```

## Convenções do projeto

- Docstrings e comentários em português, mesma língua do resto do código.
- Módulos rodam como `python -m siadar.<modulo>.<arquivo>`.
- Logging via `siadar.logging_config.get_logger(__name__)` — nada de `print()` fora de scripts
  descartáveis.
- **Nunca** commitar dados de captura reais, credenciais, ou algo que identifique uma rede real
  (a própria ou de terceiros). Veja o `.gitignore` e o `.env.example`.
- Qualquer mudança que afete o comportamento padrão da quarentena (M4) — por exemplo, deixar o
  `enforce=True` como padrão — deve ser discutida antes num PR, não decidida silenciosamente:
  é a parte do projeto com maior potencial de causar dano real.

## Código de conduta

Sem regras complicadas: seja gentil, parta do princípio de boa-fé, e trate quem está
contribuindo (inclusive você, se for a primeira vez com esse tipo de projeto) com paciência.

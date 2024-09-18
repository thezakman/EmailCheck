
# Email Check

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Email Check é uma ferramenta em Python que verifica as configurações de segurança de email de domínios, analisando registros SPF, DMARC, MTA-STS e TLS-RPT para identificar possíveis vulnerabilidades, como a possibilidade de spoofing.

## Sumário

- [Recursos](#recursos)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
  - [Analisar um único domínio](#analisar-um-único-domínio)
  - [Analisar uma lista de domínios](#analisar-uma-lista-de-domínios)
  - [Opções adicionais](#opções-adicionais)
- [Exemplos](#exemplos)
- [Contribuição](#contribuição)
- [Licença](#licença)

## Recursos

- **Análise de SPF**: Verifica se o registro SPF está configurado corretamente e se o mecanismo `all` está definido como `-all` ou `~all`.
- **Análise de DMARC**: Verifica a existência e a configuração correta do registro DMARC, incluindo políticas, relatórios e alinhamentos.
- **Análise de MTA-STS**: Verifica se o MTA-STS está configurado, melhorando a segurança no transporte de emails.
- **Análise de TLS-RPT**: Verifica se o TLS Reporting está configurado para receber relatórios de problemas de TLS.
- **Paralelização**: Utiliza threads para acelerar a análise de múltiplos domínios.
- **Saída personalizável**: Permite salvar os resultados em formato JSON para análises posteriores.
- **Flexibilidade na saída**: Exibe detalhes completos ou apenas um resumo, dependendo das preferências do usuário.

## Pré-requisitos

- Python 3.6 ou superior
- As seguintes bibliotecas Python:

  - `validators`
  - `checkdmarc`
  - `colorama`
  - `dnspython`

## Instalação

1. **Clone o repositório:**

   ```bash
   git clone https://github.com/thezakman/EmailCheck.git
   cd EmailCheck
   ```

2. **Crie um ambiente virtual (opcional, mas recomendado):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # No Windows, use: venv\Scripts\activate
   ```

3. **Instale as dependências:**

   ```bash
   pip install -r requirements.txt
   ```

   *Se não houver um arquivo `requirements.txt`, instale manualmente:*

   ```bash
   pip install validators checkdmarc colorama dnspython
   ```

## Uso

### Analisar um único domínio

Para analisar um único domínio, use a opção `-d` ou `--domain`:

```bash
python EmailCheck.py -d exemplo.com
```

*Por padrão, ao analisar um único domínio, o script exibe informações detalhadas.*

### Analisar uma lista de domínios

Para analisar múltiplos domínios a partir de um arquivo, use a opção `-f` ou `--domains_file`:

```bash
python EmailCheck.py -f domínios.txt
```

*Por padrão, ao analisar uma lista de domínios, o script exibe apenas o resumo final. Use `-v` para saída detalhada.*

### Opções adicionais

- **Salvar resultados em JSON:**

  ```bash
  python EmailCheck.py -f domínios.txt -o resultados_{timestamp}.json
  ```

  O `{timestamp}` será substituído pela data e hora atuais no formato `YYYYMMDD_HHMMSS`.

- **Especificar o número de threads:**

  ```bash
  python EmailCheck.py -f domínios.txt -t 10
  ```

  Aumente o número de threads para acelerar a análise.

- **Habilitar saída detalhada:**

  ```bash
  python EmailCheck.py -f domínios.txt -v
  ```

  Exibe informações detalhadas sobre cada domínio.

- **Exibir ajuda:**

  ```bash
  python EmailCheck.py -h
  ```

## Exemplos

**Analisando um único domínio:**

```bash
python EmailCheck.py -d exemplo.com
```

**Analisando múltiplos domínios com saída detalhada:**

```bash
python EmailCheck.py -f domínios.txt -v
```

**Salvando os resultados em um arquivo JSON:**

```bash
python EmailCheck.py -f domínios.txt -o resultados_{timestamp}.json
```

**Exemplo de saída detalhada:**

```
[+] INFO: Analisando 1 domínio(s)...

[+] INFO:

Analisando exemplo.com
[-] WARN: SPF 'all' mechanism não está definido como 'fail' ou 'softfail' para 'exemplo.com'
[-] WARN: DMARC policy não está definido corretamente para 'exemplo.com'
[-] WARN: DMARC aggregate reports (rua) não estão configurados para 'exemplo.com'
[-] WARN: DMARC forensic reports (ruf) não estão configurados para 'exemplo.com'
[-] WARN: DMARC subdomain policy (sp) não está definido para 'exemplo.com'
[+] INFO: DMARC alignment modes: SPF alignment=r, DKIM alignment=r
[+] INFO: MTA-STS policy está configurado para 'exemplo.com'
[+] INFO: TLS-RPT está configurado para 'exemplo.com'

Spoofing possível para 1 domínio(s):
  > exemplo.com
```

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues e pull requests para melhorar a ferramenta.

1. Faça um fork do projeto.
2. Crie uma nova branch para sua feature ou correção: `git checkout -b minha-feature`.
3. Commit suas mudanças: `git commit -am 'Adiciona minha feature'`.
4. Faça o push para a branch: `git push origin minha-feature`.
5. Abra um Pull Request.

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

*Nota: Esta ferramenta é destinada a auxiliar administradores de sistemas e profissionais de segurança a identificar potenciais problemas nas configurações de segurança de email. Use-a de forma responsável e ética.*

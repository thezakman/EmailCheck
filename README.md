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
   git clone https://github.com/thezakman/EmailCheck.py.git
   cd email-security-checker ```

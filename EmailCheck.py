import validators
import checkdmarc
from colorama import Fore, Style, init
import os
import sys
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import List, Dict, Any
from dataclasses import dataclass, field



@dataclass
class Config:
    MAX_SPF_LOOKUPS: int = 10
    VALID_DMARC_POLICIES: List[str] = field(default_factory=lambda: ['quarantine', 'reject'])
    DEFAULT_THREADS: int = 5

CONFIG = Config()

# Configuração do logging
def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=level
    )

# Inicializa o colorama
init(autoreset=True)

def banner():
    print(Fore.GREEN +'''
            
       ..--"""|
       | v0.9 |
       | .----'
 (\-.--| |---------.
/ \) \ | |          \\
|:.  | | |           |
|:.  | |o|           |
|:.  | `"`      2025 |
|:.  |_ __  __ _  __ /
`""""`""|=`|"""""""`
        |=_|
        |= |''', Fore.WHITE + Style.BRIGHT +'''
____    _  _ ____ _ _       ____ _  _ ____ ____ _  _ 
|___ __ |\/| |__| | |       |    |__| |___ |    |_/  
|___    |  | |  | | |___    |___ |  | |___ |___ | \_ 
                                         ''', Fore.GREEN + '''@TheZakMan
____________________________________________________
            ''')

def initialize():
    parser = argparse.ArgumentParser(
        prog="emailseccheck.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Verifica a segurança de email de domínios (SPF, DMARC, MTA-STS, TLS-RPT)."
    )

    domain_argument_group = parser.add_mutually_exclusive_group(required=True)
    domain_argument_group.add_argument("-d", "--domain", type=str,
                                       help="Domínio a ser verificado")
    domain_argument_group.add_argument("-f", "--domains_file", type=str,
                                       help="Arquivo contendo uma lista de domínios a serem verificados")
    parser.add_argument("-o", "--output-json", type=str,
                        help="Arquivo para salvar a saída em formato JSON")
    parser.add_argument("-t", "--threads", type=int, default=CONFIG.DEFAULT_THREADS,
                        help="Número de threads para paralelizar as verificações")
    parser.add_argument("-v", "--verbose", action="store_true", default=None,
                        help="Habilita saída detalhada")
    parser.add_argument("-r", "--report", action="store_true",
                        help="Gera um relatório detalhado da análise")
    args = parser.parse_args()
    main(args)


def main(args):
    setup_logging(args.verbose)
    
    if not validate_args(args):
        sys.exit(1)

    if not check_dependencies():
        sys.exit(1)

    domains_list = []

    if args.domain:
        domains_list.append(args.domain)
        if args.verbose is None:
            args.verbose = True  # Por padrão, verbose é True para -d
    else:
        domains_list = read_domains_file(args.domains_file)
        if args.verbose is None:
            args.verbose = False  # Por padrão, verbose é False para -f

    domains_list = cleanup_domains_list(domains_list)

    if domains_list:
        check_domain_security(domains_list, args)
    else:
        print_error("Nenhum domínio fornecido")


def cleanup_domains_list(domains_list):
    domains_list = [d.strip().lower() for d in domains_list if d.strip()]
    domains_list = list(dict.fromkeys(domains_list))

    domains_list.sort()
    return domains_list


def validate_args(args):
    domain_arg_valid = args.domain is None or validate_domain(args.domain)
    domain_file_arg_valid = args.domains_file is None or os.path.isfile(
        args.domains_file)

    if args.domain and not domain_arg_valid:
        print_warning("O domínio fornecido não é válido. Está formatado corretamente?")
    elif args.domains_file and not domain_file_arg_valid:
        print_warning("O arquivo de domínios não é válido ou não existe.")

    valid_args = domain_arg_valid and domain_file_arg_valid
    if not valid_args:
        print_error("Argumentos inválidos.")

    return valid_args


def validate_domain(domain: str) -> bool:
    """Valida um domínio com regras mais estritas."""
    if not domain or len(domain) > 253:
        return False
        
    if not validators.domain(domain):
        return False
        
    return True


def check_dependencies() -> bool:
    """Verifica se todas as dependências necessárias estão instaladas."""
    required = ['validators', 'checkdmarc', 'colorama']
    try:
        # Usando importlib ao invés de pkg_resources
        import importlib
        for package in required:
            importlib.import_module(package)
        return True
    except ImportError as e:
        print_error(f"Dependência faltando: {e.name}")
        return False


def check_domain_security(domains: List[str], args: argparse.Namespace) -> None:
    from contextlib import contextmanager
    
    # Inicialização das listas de resultados
    results = []
    spoofable_domains = []
    
    @contextmanager
    def executor_context(max_workers: int):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            yield executor
            
    try:
        with executor_context(args.threads) as executor:
            future_to_domain = {
                executor.submit(analyze_domain, domain, args): domain 
                for domain in domains
            }
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                    if result.get('spoofing_possible'):
                        spoofable_domains.append(domain)
                except Exception as exc:
                    print_error(f"Ocorreu um erro ao analisar '{domain}': {exc}", fatal=False)
    except Exception as e:
        logging.error(f"Erro ao executar análise: {e}")

    # Gerar e exibir o resumo apenas se --report for especificado
    if results and args.report:
        print("\n" + "="*50)
        print(generate_report_summary(results))
        print("="*50 + "\n")

    # Relatório de domínios vulneráveis sempre será mostrado
    if spoofable_domains:
        print(Fore.CYAN + Style.BRIGHT +
              f"\nSpoofing possível para {len(spoofable_domains)} domínio(s):")
        for domain in spoofable_domains:
            print(Fore.CYAN + f"  > {domain}")
    else:
        print(Fore.GREEN + Style.BRIGHT +
              "\nNenhum domínio vulnerável a spoofing foi identificado")

    # Salvar resultados em JSON se especificado
    if args.output_json:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = args.output_json.replace("{timestamp}", timestamp)
        with open(output_file, 'w') as json_file:
            json.dump(results, json_file, indent=4)
        print_info(f"Resultados salvos em {output_file}")


def analyze_domain(domain: str, args: argparse.Namespace) -> Dict[str, Any]:
    """
    Analisa a segurança de email de um domínio.
    
    Args:
        domain: O domínio a ser analisado
        args: Argumentos da linha de comando
        
    Returns:
        Dict contendo os resultados da análise
    """
    result = {'domain': domain, 'issues': [], 'spoofing_possible': False}
    verbose = args.verbose

    if verbose:
        print_info(f"\nAnalisando {domain}")

    try:
        # Análise SPF
        spf_results = checkdmarc.check_spf(domain)
        spf_record = spf_results.get('record', '')
        spf_dns_lookups = spf_results.get('dns_lookups', 0)
        spf_warnings = spf_results.get('warnings', [])
        spf_errors = spf_results.get('errors', [])
        spf_all_mechanism = spf_results.get('parsed', {}).get('all', '')

        if spf_errors:
            for error in spf_errors:
                result['issues'].append(f"SPF error: {error}")
                result['spoofing_possible'] = True
                if verbose:
                    print_warning(f"SPF error para '{domain}': {error}")

        if spf_warnings:
            for warning in spf_warnings:
                result['issues'].append(f"SPF warning: {warning}")
                if verbose:
                    print_warning(f"SPF warning para '{domain}': {warning}")

        if spf_all_mechanism not in ['-all', '~all']:
            result['issues'].append("SPF 'all' mechanism não está definido como 'fail' ou 'softfail'")
            result['spoofing_possible'] = True
            if verbose:
                print_warning(
                    f"SPF 'all' mechanism não está definido como 'fail' ou 'softfail' para '{domain}'")

        if spf_dns_lookups > CONFIG.MAX_SPF_LOOKUPS:
            result['issues'].append(f"SPF record requer muitas consultas DNS ({spf_dns_lookups})")
            if verbose:
                print_warning(
                    f"SPF record requer muitas consultas DNS ({spf_dns_lookups}) para '{domain}'")

    except checkdmarc.SPFError as e:
        result['issues'].append(f"SPF analysis error: {e}")
        result['spoofing_possible'] = True
        if verbose:
            print_error(f"SPF analysis error para '{domain}': {e}", fatal=False)
    except checkdmarc.DNSException:
        result['issues'].append("Erro geral de DNS durante análise SPF")
        if verbose:
            print_error(
                f"Erro geral de DNS durante análise SPF para '{domain}'", fatal=False)

    try:
        # Análise DMARC
        dmarc_results = checkdmarc.check_dmarc(domain)
        dmarc_record = dmarc_results.get('record', '')
        dmarc_tags = dmarc_results.get('tags', {})
        dmarc_errors = dmarc_results.get('errors', [])
        dmarc_warnings = dmarc_results.get('warnings', [])
        dmarc_policy = dmarc_tags.get('p', {}).get('value', '').lower()

        if dmarc_errors:
            for error in dmarc_errors:
                result['issues'].append(f"DMARC error: {error}")
                result['spoofing_possible'] = True
                if verbose:
                    print_warning(f"DMARC error para '{domain}': {error}")

        if dmarc_warnings:
            for warning in dmarc_warnings:
                result['issues'].append(f"DMARC warning: {warning}")
                if verbose:
                    print_warning(f"DMARC warning para '{domain}': {warning}")

        if dmarc_policy == 'none':
            result['issues'].append("DMARC policy está definido como 'none' (sem enforcement)")
            result['spoofing_possible'] = True
            if verbose:
                print_warning(
                    f"DMARC policy está definido como 'none' (sem enforcement) para '{domain}'")
        elif dmarc_policy in CONFIG.VALID_DMARC_POLICIES:
            if verbose:
                print_info(
                    f"DMARC policy está definido como '{dmarc_policy}' para '{domain}'")
        else:
            result['issues'].append("DMARC policy não está definido corretamente")
            result['spoofing_possible'] = True
            if verbose:
                print_warning(
                    f"DMARC policy não está definido corretamente para '{domain}'")

        # Verificar DMARC aggregate reports
        if 'rua' not in dmarc_tags:
            result['issues'].append("DMARC aggregate reports (rua) não estão configurados")
            if verbose:
                print_warning(
                    f"DMARC aggregate reports (rua) não estão configurados para '{domain}'")
        else:
            rua = dmarc_tags['rua']['value']
            if verbose:
                print_info(
                    f"DMARC aggregate reports serão enviados para: {rua}")

        # Verificar DMARC forensic reports
        if 'ruf' not in dmarc_tags:
            result['issues'].append("DMARC forensic reports (ruf) não estão configurados")
            if verbose:
                print_warning(
                    f"DMARC forensic reports (ruf) não estão configurados para '{domain}'")
        else:
            ruf = dmarc_tags['ruf']['value']
            if verbose:
                print_info(
                    f"DMARC forensic reports serão enviados para: {ruf}")

        # Verificar DMARC subdomain policy
        if 'sp' in dmarc_tags:
            sp_policy = dmarc_tags['sp']['value'].lower()
            if verbose:
                print_info(
                    f"DMARC subdomain policy está definido como '{sp_policy}' para '{domain}'")
        else:
            result['issues'].append("DMARC subdomain policy (sp) não está definido")
            if verbose:
                print_warning(
                    f"DMARC subdomain policy (sp) não está definido para '{domain}'")

        # Verificar DMARC alignment modes
        aspf = dmarc_tags.get('aspf', {}).get('value', 'r')
        adkim = dmarc_tags.get('adkim', {}).get('value', 'r')
        if verbose:
            print_info(
                f"DMARC alignment modes: SPF alignment={aspf}, DKIM alignment={adkim}")

    except checkdmarc.DMARCError as e:
        result['issues'].append(f"DMARC analysis error: {e}")
        result['spoofing_possible'] = True
        if verbose:
            print_error(f"DMARC analysis error para '{domain}': {e}", fatal=False)
    except checkdmarc.DNSException:
        result['issues'].append("Erro geral de DNS durante análise DMARC")
        if verbose:
            print_error(
                f"Erro geral de DNS durante análise DMARC para '{domain}'", fatal=False)

    try:
        # Análise MTA-STS
        mta_sts_results = checkdmarc.check_mta_sts(domain)
        mta_sts_errors = mta_sts_results.get('errors', [])
        if mta_sts_errors:
            for error in mta_sts_errors:
                result['issues'].append(f"MTA-STS error: {error}")
                if verbose:
                    print_warning(f"MTA-STS error para '{domain}': {error}")
        else:
            if verbose:
                print_info(f"MTA-STS policy está configurado para '{domain}'")
    except checkdmarc.MTASTSError as e:
        result['issues'].append(f"MTA-STS analysis error: {e}")
        if verbose:
            print_warning(f"MTA-STS analysis error para '{domain}': {e}")
    except checkdmarc.DNSException:
        result['issues'].append("Erro geral de DNS durante análise MTA-STS")
        if verbose:
            print_error(
                f"Erro geral de DNS durante análise MTA-STS para '{domain}'", fatal=False)

    try:
        # Análise TLS-RPT
        tls_rpt_results = checkdmarc.check_smtp_tls_reporting(domain)
        tls_rpt_errors = tls_rpt_results.get('errors', [])
        if tls_rpt_errors:
            for error in tls_rpt_errors:
                result['issues'].append(f"TLS-RPT error: {error}")
                if verbose:
                    print_warning(f"TLS-RPT error para '{domain}': {error}")
        else:
            if verbose:
                print_info(f"TLS-RPT está configurado para '{domain}'")
    except checkdmarc.SMTPTLSReportingError as e:
        result['issues'].append(f"TLS-RPT analysis error: {e}")
        if verbose:
            print_warning(f"TLS-RPT analysis error para '{domain}': {e}")
    except checkdmarc.DNSException:
        result['issues'].append("Erro geral de DNS durante análise TLS-RPT")
        if verbose:
            print_error(
                f"Erro geral de DNS durante análise TLS-RPT para '{domain}'", fatal=False)

    return result


def print_error(message, fatal=True):
    print(Fore.RED + Style.BRIGHT + f"[!] ERROR: {message}")
    if fatal:
        sys.exit(1)


def print_warning(message):
    print(Fore.YELLOW + Style.BRIGHT + f"[-] WARN: {message}")


def print_info(message):
    print(Fore.LIGHTBLUE_EX + Style.BRIGHT + f"[+] INFO: {message}")


def format_results(results: List[Dict[str, Any]], timestamp: str) -> Dict[str, Any]:
    """Formata os resultados para JSON."""
    return {
        "scan_timestamp": timestamp,
        "total_domains": len(results),
        "vulnerable_domains": sum(1 for r in results if r.get('spoofing_possible')),
        "results": results,
        "metadata": {
            "tool_version": "1.0.0",
            "scan_date": datetime.now().isoformat()
        }
    }


def read_domains_file(file_path: str) -> List[str]:
    """Lê domínios de um arquivo de forma segura."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except Exception as e:
        logging.error(f"Erro ao ler arquivo de domínios: {e}")
        return []


def generate_report_summary(results: List[Dict[str, Any]]) -> str:
    """Gera um resumo detalhado dos resultados."""
    total_domains = len(results)
    vulnerable_domains = sum(1 for r in results if r.get('spoofing_possible'))
    
    summary = f"""
📊 Resumo da Análise
===================
Total de domínios analisados: {total_domains}
Domínios vulneráveis: {vulnerable_domains}
Taxa de vulnerabilidade: {(vulnerable_domains/total_domains)*100:.1f}%

🔍 Principais Problemas Encontrados:
"""
    # Agregação de problemas comuns
    issues_count = {}
    for result in results:
        for issue in result['issues']:
            issues_count[issue] = issues_count.get(issue, 0) + 1
            
    for issue, count in sorted(issues_count.items(), key=lambda x: x[1], reverse=True):
        summary += f"- {issue}: {count} ocorrência(s)\n"
        
    return summary


if __name__ == "__main__":
    banner()
    initialize()

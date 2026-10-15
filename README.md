# WS Monitor

Aplicativo para Windows desenvolvido por WS Dev. O programa verifica a disponibilidade e a resposta HTTP de um site a cada 30 segundos e pode acompanhar novas linhas de um log de acesso Apache/Nginx.

## Recursos

- Interface escura com detalhes em verde-lima.
- Monitoramento HTTP/HTTPS com indicação de status, tempo de resposta e cabeçalhos de segurança ausentes.
- Análise opcional de logs Apache/Nginx para padrões compatíveis com SQL injection, XSS, traversal, injeção de comandos, tentativas repetidas em rotas de autenticação e picos de tráfego.
- Aviso na tela ao detectar um padrão nos logs.
- Relatório PDF sob demanda e relatório final automático ao parar ou fechar o aplicativo.

## Executar

Instale Python 3.10 ou superior no Windows e execute:

```text
py ws_monitor.py
```

Digite o endereço do site. Para analisar tentativas vistas pelo servidor, selecione também o arquivo de log de acesso (por exemplo, um log Apache ou Nginx). O aplicativo acompanha apenas linhas adicionadas depois do início do monitoramento.

## Criar o executável

No Windows, execute `build.bat`. O script instala PyInstaller e cria `dist\WS Monitor.exe`.

## Limites importantes

Sem acesso a logs do servidor, o aplicativo só consegue observar respostas HTTP públicas e cabeçalhos; não consegue identificar tentativas de ataque que não sejam visíveis externamente. As detecções em logs são heurísticas, inclusive a classificação de força bruta e picos de tráfego. O aplicativo não bloqueia requisições, não substitui WAF/IDS e não garante detectar todos os ataques. Use-o somente em sites e logs que você tem autorização para monitorar.

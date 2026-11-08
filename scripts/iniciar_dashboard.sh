#!/bin/bash
# iniciar_dashboard.sh — Inicia o dashboard Firewall IA em background
# Uso: bash iniciar_dashboard.sh [start|stop|restart|status]

PROJETO="/home/aparecido/firewall-ia"
SCRIPT="scripts/dashboard.py"
VENV="${PROJETO}/.venv/bin/python"
PORTA=8080
PIDFILE="/tmp/dashboard_firewall_ia.pid"
LOGFILE="${PROJETO}/reports/dashboard.log"

caso="${1:-start}"

caso_start() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        echo "[INFO] Dashboard já está rodando (PID $(cat $PIDFILE))"
        echo "       Acesse: http://172.16.0.125:${PORTA}"
        exit 0
    fi
    mkdir -p "${PROJETO}/reports"
    echo "[INFO] Iniciando dashboard na porta ${PORTA}..."
    cd "$PROJETO" || exit 1
    nohup "$VENV" "$SCRIPT" --port "$PORTA" >> "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 3
    if kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        echo "[OK]  Dashboard rodando (PID $(cat $PIDFILE))"
        echo "      Acesse: http://172.16.0.125:${PORTA}"
        echo "      Log:    $LOGFILE"
    else
        echo "[ERRO] Falha ao iniciar. Verifique: $LOGFILE"
        cat "$LOGFILE" | tail -20
        exit 1
    fi
}

caso_stop() {
    if [ -f "$PIDFILE" ]; then
        PID=$(cat "$PIDFILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID"
            rm -f "$PIDFILE"
            echo "[OK] Dashboard parado (PID $PID)"
        else
            echo "[INFO] Processo $PID não encontrado (já parado?)"
            rm -f "$PIDFILE"
        fi
    else
        echo "[INFO] PIDFILE não encontrado — dashboard pode não estar rodando."
        # Tenta matar pelo nome mesmo assim
        pkill -f "dashboard.py" && echo "[OK] Processo encerrado via pkill."
    fi
}

caso_status() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        PID=$(cat "$PIDFILE")
        echo "[OK] Dashboard rodando — PID $PID"
        echo "     Acesse: http://172.16.0.125:${PORTA}"
        curl -s "http://localhost:${PORTA}/api/status" | python3 -m json.tool 2>/dev/null || true
    else
        echo "[PARADO] Dashboard não está rodando."
    fi
}

case "$caso" in
    start)   caso_start   ;;
    stop)    caso_stop    ;;
    restart) caso_stop; sleep 1; caso_start ;;
    status)  caso_status  ;;
    *)
        echo "Uso: $0 [start|stop|restart|status]"
        exit 1
        ;;
esac

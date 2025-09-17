package web

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/JimmyRamsamynaick/LogSentinel/internal/watcher"
	"github.com/JimmyRamsamynaick/LogSentinel/pkg/config"
)

// WebServer représente le serveur web
type WebServer struct {
	config     *config.Config
	server     *http.Server
	watchers   []*watcher.LogWatcher
	clients    map[*websocket.Conn]bool
	clientsMux sync.RWMutex
	upgrader   websocket.Upgrader
}

// LogMessage représente un message de log pour WebSocket
type LogMessage struct {
	Timestamp string `json:"timestamp"`
	FilePath  string `json:"file_path"`
	Line      string `json:"line"`
	Severity  string `json:"severity"`
	Pattern   string `json:"pattern"`
}

// StatsResponse représente la réponse des statistiques
type StatsResponse struct {
	TotalFiles      int                    `json:"total_files"`
	TotalLines      int64                  `json:"total_lines"`
	TotalAlerts     int64                  `json:"total_alerts"`
	FileStats       []FileStats            `json:"file_stats"`
	SystemInfo      map[string]interface{} `json:"system_info"`
	LastUpdate      time.Time              `json:"last_update"`
}

// FileStats représente les statistiques d'un fichier
type FileStats struct {
	FilePath       string `json:"file_path"`
	LinesProcessed int64  `json:"lines_processed"`
	AlertsSent     int64  `json:"alerts_sent"`
	IsRunning      bool   `json:"is_running"`
}

// NewWebServer crée une nouvelle instance du serveur web
func NewWebServer(cfg *config.Config) *WebServer {
	return &WebServer{
		config:  cfg,
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Permettre toutes les origines pour le développement
			},
		},
	}
}

// Start démarre le serveur web
func (ws *WebServer) Start() error {
	router := mux.NewRouter()

	// Routes API
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/stats", ws.handleStats).Methods("GET")
	api.HandleFunc("/config", ws.handleConfig).Methods("GET", "POST")
	api.HandleFunc("/logs", ws.handleLogs).Methods("GET")
	api.HandleFunc("/alerts", ws.handleAlerts).Methods("GET")

	// WebSocket
	router.HandleFunc("/ws", ws.handleWebSocket)

	// Interface web statique
	router.HandleFunc("/", ws.handleIndex)
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("web/static/"))))

	// Démarrer les watchers
	ws.startWatchers()

	// Configuration du serveur
	ws.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", ws.config.Web.Host, ws.config.Web.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return ws.server.ListenAndServe()
}

// Stop arrête le serveur web
func (ws *WebServer) Stop() error {
	// Arrêter les watchers
	for _, w := range ws.watchers {
		w.Stop()
	}

	// Fermer les connexions WebSocket
	ws.clientsMux.Lock()
	for client := range ws.clients {
		client.Close()
	}
	ws.clientsMux.Unlock()

	// Arrêter le serveur HTTP
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ws.server.Shutdown(ctx)
}

// startWatchers démarre les watchers pour tous les fichiers configurés
func (ws *WebServer) startWatchers() {
	for _, logConfig := range ws.config.Logs {
		if !logConfig.Enabled {
			continue
		}

		w, err := watcher.NewLogWatcher(logConfig.Path, ws.config)
		if err != nil {
			fmt.Printf("❌ Erreur lors de la création du watcher pour %s: %v\n", logConfig.Path, err)
			continue
		}

		// Configurer la diffusion WebSocket
		w.SetWebBroadcaster(func(entry watcher.LogEntry) {
			msg := LogMessage{
				Timestamp: entry.Timestamp.Format("15:04:05"),
				FilePath:  entry.FilePath,
				Line:      entry.Line,
				Severity:  "info", // Par défaut, peut être amélioré avec la détection
				Pattern:   "",
			}
			ws.BroadcastLogMessage(msg)
		})

		go func(watcher *watcher.LogWatcher) {
			if err := watcher.Start(); err != nil {
				fmt.Printf("❌ Erreur lors du démarrage du watcher: %v\n", err)
			}
		}(w)

		ws.watchers = append(ws.watchers, w)
	}
}

// handleIndex sert la page d'accueil
func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := `
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogSentinel - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a1a; color: #fff; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 1rem; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: #2d2d2d; padding: 1.5rem; border-radius: 8px; border-left: 4px solid #667eea; }
        .stat-value { font-size: 2rem; font-weight: bold; color: #667eea; }
        .stat-label { color: #ccc; margin-top: 0.5rem; }
        .logs-container { background: #2d2d2d; border-radius: 8px; padding: 1rem; height: 400px; overflow-y: auto; }
        .log-entry { padding: 0.5rem; border-bottom: 1px solid #444; font-family: monospace; font-size: 0.9rem; }
        .log-error { border-left: 3px solid #e74c3c; background: rgba(231, 76, 60, 0.1); }
        .log-warning { border-left: 3px solid #f39c12; background: rgba(243, 156, 18, 0.1); }
        .log-info { border-left: 3px solid #3498db; background: rgba(52, 152, 219, 0.1); }
        .timestamp { color: #888; margin-right: 1rem; }
        .file-path { color: #667eea; margin-right: 1rem; }
        .controls { margin-bottom: 1rem; }
        .btn { background: #667eea; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; margin-right: 0.5rem; }
        .btn:hover { background: #5a6fd8; }
        .status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 0.5rem; }
        .status.connected { background: #2ecc71; }
        .status.disconnected { background: #e74c3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🕵️‍♂️ LogSentinel Dashboard</h1>
        <p>Surveillance de logs en temps réel</p>
    </div>
    
    <div class="container">
        <div class="controls">
            <span class="status connected" id="wsStatus"></span>
            <span id="wsStatusText">Connecté</span>
            <button class="btn" onclick="clearLogs()">Effacer les logs</button>
            <button class="btn" onclick="togglePause()">Pause</button>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="totalFiles">{{.TotalFiles}}</div>
                <div class="stat-label">Fichiers surveillés</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalLines">0</div>
                <div class="stat-label">Lignes traitées</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalAlerts">0</div>
                <div class="stat-label">Alertes envoyées</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="uptime">00:00:00</div>
                <div class="stat-label">Temps de fonctionnement</div>
            </div>
        </div>
        
        <div class="logs-container" id="logsContainer">
            <div class="log-entry">En attente des logs...</div>
        </div>
    </div>

    <script>
        let ws;
        let isPaused = false;
        let startTime = new Date();
        
        function connectWebSocket() {
            ws = new WebSocket('ws://localhost:{{.Port}}/ws');
            
            ws.onopen = function() {
                document.getElementById('wsStatus').className = 'status connected';
                document.getElementById('wsStatusText').textContent = 'Connecté';
            };
            
            ws.onmessage = function(event) {
                if (!isPaused) {
                    const data = JSON.parse(event.data);
                    addLogEntry(data);
                }
            };
            
            ws.onclose = function() {
                document.getElementById('wsStatus').className = 'status disconnected';
                document.getElementById('wsStatusText').textContent = 'Déconnecté';
                setTimeout(connectWebSocket, 3000);
            };
        }
        
        function addLogEntry(data) {
            const container = document.getElementById('logsContainer');
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            
            if (data.severity === 'high' || data.line.includes('ERROR')) {
                entry.className += ' log-error';
            } else if (data.severity === 'medium' || data.line.includes('WARN')) {
                entry.className += ' log-warning';
            } else {
                entry.className += ' log-info';
            }
            
            entry.innerHTML = 
                '<span class="timestamp">' + data.timestamp + '</span>' +
                '<span class="file-path">' + data.file_path + '</span>' +
                '<span>' + data.line + '</span>';
            
            container.insertBefore(entry, container.firstChild);
            
            // Limiter à 100 entrées
            while (container.children.length > 100) {
                container.removeChild(container.lastChild);
            }
        }
        
        function clearLogs() {
            document.getElementById('logsContainer').innerHTML = '<div class="log-entry">Logs effacés...</div>';
        }
        
        function togglePause() {
            isPaused = !isPaused;
            document.querySelector('button[onclick="togglePause()"]').textContent = isPaused ? 'Reprendre' : 'Pause';
        }
        
        function updateStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('totalLines').textContent = data.total_lines;
                    document.getElementById('totalAlerts').textContent = data.total_alerts;
                });
        }
        
        function updateUptime() {
            const now = new Date();
            const diff = now - startTime;
            const hours = Math.floor(diff / 3600000);
            const minutes = Math.floor((diff % 3600000) / 60000);
            const seconds = Math.floor((diff % 60000) / 1000);
            document.getElementById('uptime').textContent = 
                String(hours).padStart(2, '0') + ':' + 
                String(minutes).padStart(2, '0') + ':' + 
                String(seconds).padStart(2, '0');
        }
        
        connectWebSocket();
        setInterval(updateStats, 5000);
        setInterval(updateUptime, 1000);
    </script>
</body>
</html>`

	t, err := template.New("index").Parse(tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		TotalFiles int
		Port       int
	}{
		TotalFiles: len(ws.config.Logs),
		Port:       ws.config.Web.Port,
	}

	w.Header().Set("Content-Type", "text/html")
	t.Execute(w, data)
}

// handleWebSocket gère les connexions WebSocket
func (ws *WebServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("❌ Erreur WebSocket: %v\n", err)
		return
	}
	defer conn.Close()

	ws.clientsMux.Lock()
	ws.clients[conn] = true
	ws.clientsMux.Unlock()

	defer func() {
		ws.clientsMux.Lock()
		delete(ws.clients, conn)
		ws.clientsMux.Unlock()
	}()

	// Garder la connexion ouverte
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// handleStats retourne les statistiques
func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	var totalLines, totalAlerts int64
	var fileStats []FileStats

	for _, watcher := range ws.watchers {
		stats := watcher.GetStats()
		totalLines += stats.LinesProcessed
		totalAlerts += stats.AlertsSent

		fileStats = append(fileStats, FileStats{
			FilePath:       stats.FilePath,
			LinesProcessed: stats.LinesProcessed,
			AlertsSent:     stats.AlertsSent,
			IsRunning:      stats.IsRunning,
		})
	}

	response := StatsResponse{
		TotalFiles:  len(ws.config.Logs),
		TotalLines:  totalLines,
		TotalAlerts: totalAlerts,
		FileStats:   fileStats,
		SystemInfo: map[string]interface{}{
			"version": "1.0.0",
			"uptime":  time.Since(time.Now()).String(),
		},
		LastUpdate: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleConfig gère la configuration
func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ws.config)
	} else if r.Method == "POST" {
		// TODO: Implémenter la mise à jour de configuration
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("Configuration update not implemented yet"))
	}
}

// handleLogs retourne les logs récents
func (ws *WebServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	// TODO: Implémenter la récupération des logs
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("[]"))
}

// handleAlerts retourne les alertes récentes
func (ws *WebServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	// TODO: Implémenter la récupération des alertes
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("[]"))
}

// BroadcastLogMessage diffuse un message de log à tous les clients WebSocket
func (ws *WebServer) BroadcastLogMessage(msg LogMessage) {
	ws.clientsMux.RLock()
	defer ws.clientsMux.RUnlock()

	for client := range ws.clients {
		err := client.WriteJSON(msg)
		if err != nil {
			client.Close()
			delete(ws.clients, client)
		}
	}
}
package watcher

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JimmyRamsamynaick/LogSentinel/internal/detector"
	"github.com/JimmyRamsamynaick/LogSentinel/pkg/config"
)

// LogWatcher représente un surveillant pour un fichier de log spécifique
type LogWatcher struct {
	filePath        string
	config          *config.Config
	detector        *detector.Detector
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	linesProcessed  int64
	alertsSent      int64
	isRunning       bool
	mu              sync.RWMutex
	webBroadcaster  func(LogEntry) // Fonction pour diffuser vers l'interface web
}

// Stats représente les statistiques d'un LogWatcher
type Stats struct {
	LinesProcessed int64
	AlertsSent     int64
	IsRunning      bool
	FilePath       string
}

// NewLogWatcher crée une nouvelle instance de LogWatcher pour un fichier spécifique
func NewLogWatcher(filePath string, cfg *config.Config) (*LogWatcher, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration invalide: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	det, err := detector.New(cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("erreur lors de l'initialisation du détecteur: %w", err)
	}

	return &LogWatcher{
		filePath: filePath,
		config:   cfg,
		detector: det,
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// SetWebBroadcaster définit la fonction de diffusion vers l'interface web
func (lw *LogWatcher) SetWebBroadcaster(broadcaster func(LogEntry)) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	lw.webBroadcaster = broadcaster
}

// Start démarre la surveillance du fichier de log
func (lw *LogWatcher) Start() error {
	lw.mu.Lock()
	if lw.isRunning {
		lw.mu.Unlock()
		return fmt.Errorf("le watcher est déjà en cours d'exécution")
	}
	lw.isRunning = true
	lw.mu.Unlock()

	// Vérifier que le fichier existe
	if _, err := os.Stat(lw.filePath); os.IsNotExist(err) {
		return fmt.Errorf("le fichier %s n'existe pas", lw.filePath)
	}

	// Canal pour les entrées de log
	logChan := make(chan LogEntry, 100)

	// Démarrer le processeur d'entrées de log
	lw.wg.Add(1)
	go lw.processLogEntries(logChan)

	// Démarrer la surveillance du fichier
	lw.wg.Add(1)
	go lw.watchFile(logChan)

	return nil
}

// Stop arrête la surveillance du fichier de log
func (lw *LogWatcher) Stop() {
	lw.mu.Lock()
	if !lw.isRunning {
		lw.mu.Unlock()
		return
	}
	lw.isRunning = false
	lw.mu.Unlock()

	lw.cancel()
	lw.wg.Wait()
}

// GetStats retourne les statistiques du LogWatcher
func (lw *LogWatcher) GetStats() Stats {
	lw.mu.RLock()
	defer lw.mu.RUnlock()

	return Stats{
		LinesProcessed: atomic.LoadInt64(&lw.linesProcessed),
		AlertsSent:     atomic.LoadInt64(&lw.alertsSent),
		IsRunning:      lw.isRunning,
		FilePath:       lw.filePath,
	}
}

// watchFile surveille le fichier de log et envoie les nouvelles lignes
func (lw *LogWatcher) watchFile(logChan chan<- LogEntry) {
	defer lw.wg.Done()
	defer close(logChan)

	file, err := os.Open(lw.filePath)
	if err != nil {
		fmt.Printf("❌ Erreur lors de l'ouverture du fichier %s: %v\n", lw.filePath, err)
		return
	}
	defer file.Close()

	// Aller à la fin du fichier pour ne lire que les nouvelles lignes
	file.Seek(0, 2)

	scanner := bufio.NewScanner(file)
	lineNum := int64(0)

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-lw.ctx.Done():
			return
		case <-ticker.C:
			// Lire les nouvelles lignes
			for scanner.Scan() {
				line := scanner.Text()
				lineNum++

				entry := LogEntry{
					FilePath:  lw.filePath,
					Line:      line,
					Timestamp: time.Now(),
					LineNum:   lineNum,
				}

				select {
				case logChan <- entry:
					atomic.AddInt64(&lw.linesProcessed, 1)
				case <-lw.ctx.Done():
					return
				}
			}

			if err := scanner.Err(); err != nil {
				fmt.Printf("❌ Erreur lors de la lecture du fichier %s: %v\n", lw.filePath, err)
				return
			}
		}
	}
}

// processLogEntries traite les entrées de log et déclenche les alertes
func (lw *LogWatcher) processLogEntries(logChan <-chan LogEntry) {
	defer lw.wg.Done()

	for {
		select {
		case entry, ok := <-logChan:
			if !ok {
				return
			}

			// Diffuser vers l'interface web si configuré
			lw.mu.RLock()
			if lw.webBroadcaster != nil {
				lw.webBroadcaster(entry)
			}
			lw.mu.RUnlock()

			// Traiter l'entrée avec le détecteur
			lw.detector.ProcessLogEntry(entry.Line, entry.FilePath, entry.Timestamp)
			atomic.AddInt64(&lw.alertsSent, 1)

		case <-lw.ctx.Done():
			return
		}
	}
}
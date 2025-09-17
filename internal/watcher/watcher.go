package watcher

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/JimmyRamsamynaick/LogSentinel/internal/detector"
	"github.com/JimmyRamsamynaick/LogSentinel/pkg/config"
)

// Watcher représente le surveillant de fichiers de logs
type Watcher struct {
	config   *config.Config
	detector *detector.Detector
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// LogEntry représente une entrée de log
type LogEntry struct {
	FilePath  string    `json:"file_path"`
	Line      string    `json:"line"`
	Timestamp time.Time `json:"timestamp"`
	LineNum   int64     `json:"line_num"`
}

// New crée une nouvelle instance de Watcher
func New(cfg *config.Config) (*Watcher, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration invalide: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	det, err := detector.New(cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("erreur lors de l'initialisation du détecteur: %w", err)
	}

	return &Watcher{
		config:   cfg,
		detector: det,
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// Start démarre la surveillance de tous les fichiers configurés
func (w *Watcher) Start() error {
	fmt.Println("🚀 Démarrage de LogSentinel...")

	// Démarrer le détecteur
	if err := w.detector.Start(); err != nil {
		return fmt.Errorf("erreur lors du démarrage du détecteur: %w", err)
	}

	// Créer un canal pour recevoir les entrées de log
	logChan := make(chan LogEntry, 100)

	// Démarrer le processeur d'entrées de log
	w.wg.Add(1)
	go w.processLogEntries(logChan)

	// Démarrer la surveillance de chaque fichier
	for _, logConfig := range w.config.Logs {
		if !logConfig.Enabled {
			continue
		}

		w.wg.Add(1)
		go w.watchFile(logConfig, logChan)
		fmt.Printf("📁 Surveillance démarrée: %s\n", logConfig.Path)
	}

	// Attendre un peu pour que les goroutines traitent les données
	time.Sleep(2 * time.Second)

	// Fermer le canal et attendre la fin du traitement
	close(logChan)
	w.wg.Wait()

	return nil
}

// Stop arrête la surveillance
func (w *Watcher) Stop() {
	fmt.Println("🛑 Arrêt de LogSentinel...")
	w.cancel()
	w.detector.Stop()
}

// watchFile surveille un fichier spécifique
func (w *Watcher) watchFile(logConfig config.LogConfig, logChan chan<- LogEntry) {
	defer w.wg.Done()

	// Lire le contenu existant du fichier une seule fois
	if err := w.readExistingContent(logConfig.Path, logChan); err != nil {
		fmt.Printf("❌ Erreur lors de la lecture initiale de %s: %v\n", logConfig.Path, err)
	}

	// Maintenant surveiller les nouvelles modifications (simulation)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			// Pour cette version de test, on ne fait que vérifier le contexte
			// Dans une vraie implémentation, on utiliserait fsnotify ou inotify
		}
	}
}

// readExistingContent lit le contenu existant du fichier
func (w *Watcher) readExistingContent(filePath string, logChan chan<- LogEntry) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("impossible d'ouvrir le fichier %s: %w", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := int64(0)

	for scanner.Scan() {
		select {
		case <-w.ctx.Done():
			return nil
		default:
			lineNum++
			line := scanner.Text()
			if line != "" {
				logChan <- LogEntry{
					FilePath:  filePath,
					Line:      line,
					Timestamp: time.Now(),
					LineNum:   lineNum,
				}
			}
		}
	}

	return scanner.Err()
}

// tailFile implémente la fonctionnalité tail -f
func (w *Watcher) tailFile(filePath string, logChan chan<- LogEntry) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("impossible d'ouvrir le fichier %s: %w", filePath, err)
	}
	defer file.Close()

	// Lire le fichier depuis le début pour les tests
	scanner := bufio.NewScanner(file)
	lineNum := int64(0)

	// Lire le contenu existant
	for scanner.Scan() {
		select {
		case <-w.ctx.Done():
			return nil
		default:
			lineNum++
			line := scanner.Text()
			if line != "" {
				logChan <- LogEntry{
					FilePath:  filePath,
					Line:      line,
					Timestamp: time.Now(),
					LineNum:   lineNum,
				}
			}
		}
	}

	// Maintenant surveiller les nouvelles lignes
	for {
		select {
		case <-w.ctx.Done():
			return nil
		default:
			if scanner.Scan() {
				lineNum++
				entry := LogEntry{
					FilePath:  filePath,
					Line:      scanner.Text(),
					Timestamp: time.Now(),
					LineNum:   lineNum,
				}

				select {
				case logChan <- entry:
				case <-w.ctx.Done():
					return nil
				}
			} else {
				// Pas de nouvelles lignes, attendre un peu
				time.Sleep(100 * time.Millisecond)
				
				// Vérifier si le fichier a été tronqué ou supprimé
				if stat, err := file.Stat(); err != nil || stat.Size() == 0 {
					return fmt.Errorf("fichier modifié ou supprimé")
				}
			}
		}
	}
}

// processLogEntries traite les entrées de log reçues
func (w *Watcher) processLogEntries(logChan <-chan LogEntry) {
	defer w.wg.Done()

	for {
		select {
		case <-w.ctx.Done():
			return
		case entry, ok := <-logChan:
			if !ok {
				return
			}
			
			// Envoyer l'entrée au détecteur
			w.detector.ProcessLogEntry(entry.FilePath, entry.Line, entry.Timestamp)
		}
	}
}

// GetStats retourne les statistiques de surveillance
func (w *Watcher) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"files_watched": len(w.config.Logs),
		"detector_stats": w.detector.GetStats(),
	}
}
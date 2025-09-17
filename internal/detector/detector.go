package detector

import (
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/JimmyRamsamynaick/LogSentinel/internal/alerter"
	"github.com/JimmyRamsamynaick/LogSentinel/pkg/config"
)

// Detector représente le détecteur de motifs
type Detector struct {
	config   *config.Config
	alerter  *alerter.Alerter
	patterns map[string][]*CompiledPattern
	stats    *Stats
	mutex    sync.RWMutex
}

// CompiledPattern représente un motif compilé
type CompiledPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string
	Enabled  bool
}

// Match représente une correspondance trouvée
type Match struct {
	FilePath  string    `json:"file_path"`
	Line      string    `json:"line"`
	Pattern   string    `json:"pattern"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

// Stats représente les statistiques du détecteur
type Stats struct {
	TotalLines    int64            `json:"total_lines"`
	TotalMatches  int64            `json:"total_matches"`
	MatchesBySeverity map[string]int64 `json:"matches_by_severity"`
	MatchesByPattern  map[string]int64 `json:"matches_by_pattern"`
	LastMatch     *Match           `json:"last_match"`
	StartTime     time.Time        `json:"start_time"`
	mutex         sync.RWMutex
}

// New crée une nouvelle instance de Detector
func New(cfg *config.Config) (*Detector, error) {
	alerter, err := alerter.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'initialisation de l'alerter: %w", err)
	}

	detector := &Detector{
		config:   cfg,
		alerter:  alerter,
		patterns: make(map[string][]*CompiledPattern),
		stats: &Stats{
			MatchesBySeverity: make(map[string]int64),
			MatchesByPattern:  make(map[string]int64),
			StartTime:         time.Now(),
		},
	}

	// Compiler les motifs
	if err := detector.compilePatterns(); err != nil {
		return nil, fmt.Errorf("erreur lors de la compilation des motifs: %w", err)
	}

	return detector, nil
}

// compilePatterns compile tous les motifs regex
func (d *Detector) compilePatterns() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	for _, logConfig := range d.config.Logs {
		var compiledPatterns []*CompiledPattern

		for _, pattern := range logConfig.Patterns {
			if !pattern.Enabled {
				continue
			}

			regex, err := regexp.Compile(pattern.Regex)
			if err != nil {
				return fmt.Errorf("erreur lors de la compilation du motif '%s': %w", pattern.Name, err)
			}

			compiledPatterns = append(compiledPatterns, &CompiledPattern{
				Name:     pattern.Name,
				Regex:    regex,
				Severity: pattern.Severity,
				Enabled:  pattern.Enabled,
			})
		}

		d.patterns[logConfig.Path] = compiledPatterns
	}

	return nil
}

// Start démarre le détecteur
func (d *Detector) Start() error {
	fmt.Println("🔍 Détecteur de motifs démarré")
	return d.alerter.Start()
}

// Stop arrête le détecteur
func (d *Detector) Stop() {
	fmt.Println("🔍 Arrêt du détecteur de motifs")
	d.alerter.Stop()
}

// ProcessLogEntry traite une entrée de log
func (d *Detector) ProcessLogEntry(filePath, line string, timestamp time.Time) {
	d.stats.mutex.Lock()
	d.stats.TotalLines++
	d.stats.mutex.Unlock()

	d.mutex.RLock()
	patterns, exists := d.patterns[filePath]
	d.mutex.RUnlock()

	if !exists {
		return
	}

	// Tester chaque motif
	for _, pattern := range patterns {
		if !pattern.Enabled {
			continue
		}

		if pattern.Regex.MatchString(line) {
			match := &Match{
				FilePath:  filePath,
				Line:      line,
				Pattern:   pattern.Name,
				Severity:  pattern.Severity,
				Timestamp: timestamp,
			}

			d.handleMatch(match)
		}
	}
}

// handleMatch gère une correspondance trouvée
func (d *Detector) handleMatch(match *Match) {
	// Mettre à jour les statistiques
	d.stats.mutex.Lock()
	d.stats.TotalMatches++
	d.stats.MatchesBySeverity[match.Severity]++
	d.stats.MatchesByPattern[match.Pattern]++
	d.stats.LastMatch = match
	d.stats.mutex.Unlock()

	// Afficher dans la console avec couleurs
	d.printColoredMatch(match)

	// Envoyer l'alerte
	alertMatch := &alerter.Match{
		FilePath:  match.FilePath,
		Line:      match.Line,
		Pattern:   match.Pattern,
		Severity:  match.Severity,
		Timestamp: match.Timestamp,
	}
	d.alerter.SendAlert(alertMatch)
}

// printColoredMatch affiche une correspondance avec des couleurs
func (d *Detector) printColoredMatch(match *Match) {
	if !d.config.Alerts.Console.Enabled {
		return
	}

	var color string
	var emoji string

	switch match.Severity {
	case "critical":
		color = "\033[1;31m" // Rouge gras
		emoji = "🚨"
	case "high":
		color = "\033[31m" // Rouge
		emoji = "❗"
	case "medium":
		color = "\033[33m" // Jaune
		emoji = "⚠️"
	case "low":
		color = "\033[36m" // Cyan
		emoji = "ℹ️"
	default:
		color = "\033[37m" // Blanc
		emoji = "📝"
	}

	reset := "\033[0m"
	if !d.config.Alerts.Console.Colors {
		color = ""
		reset = ""
	}

	fmt.Printf("%s%s [%s] %s - %s: %s%s\n",
		color,
		emoji,
		match.Timestamp.Format("15:04:05"),
		match.Severity,
		match.Pattern,
		match.Line,
		reset,
	)
}

// GetStats retourne les statistiques du détecteur
func (d *Detector) GetStats() *Stats {
	d.stats.mutex.RLock()
	defer d.stats.mutex.RUnlock()

	// Créer une copie pour éviter les races conditions
	statsCopy := &Stats{
		TotalLines:        d.stats.TotalLines,
		TotalMatches:      d.stats.TotalMatches,
		MatchesBySeverity: make(map[string]int64),
		MatchesByPattern:  make(map[string]int64),
		LastMatch:         d.stats.LastMatch,
		StartTime:         d.stats.StartTime,
	}

	for k, v := range d.stats.MatchesBySeverity {
		statsCopy.MatchesBySeverity[k] = v
	}

	for k, v := range d.stats.MatchesByPattern {
		statsCopy.MatchesByPattern[k] = v
	}

	return statsCopy
}

// AddPattern ajoute un nouveau motif dynamiquement
func (d *Detector) AddPattern(filePath string, pattern config.Pattern) error {
	regex, err := regexp.Compile(pattern.Regex)
	if err != nil {
		return fmt.Errorf("erreur lors de la compilation du motif: %w", err)
	}

	compiledPattern := &CompiledPattern{
		Name:     pattern.Name,
		Regex:    regex,
		Severity: pattern.Severity,
		Enabled:  pattern.Enabled,
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.patterns[filePath] = append(d.patterns[filePath], compiledPattern)
	return nil
}

// RemovePattern supprime un motif
func (d *Detector) RemovePattern(filePath, patternName string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	patterns := d.patterns[filePath]
	for i, pattern := range patterns {
		if pattern.Name == patternName {
			d.patterns[filePath] = append(patterns[:i], patterns[i+1:]...)
			break
		}
	}
}
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/JimmyRamsamynaick/LogSentinel/pkg/config"
)

// Storage représente le système de stockage des alertes
type Storage struct {
	config config.StorageConfig
	mutex  sync.RWMutex
}

// Alert représente une alerte stockée
type Alert struct {
	ID        string    `json:"id"`
	FilePath  string    `json:"file_path"`
	Line      string    `json:"line"`
	Pattern   string    `json:"pattern"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
	Sent      bool      `json:"sent"`
	Channels  []string  `json:"channels"`
}

// AlertsData représente la structure de données pour le stockage JSON
type AlertsData struct {
	Alerts    []*Alert  `json:"alerts"`
	LastSaved time.Time `json:"last_saved"`
	Version   string    `json:"version"`
}

// New crée une nouvelle instance de Storage
func New(cfg config.StorageConfig) (*Storage, error) {
	storage := &Storage{
		config: cfg,
	}

	// Créer le fichier de stockage s'il n'existe pas
	if err := storage.initialize(); err != nil {
		return nil, fmt.Errorf("erreur lors de l'initialisation du stockage: %w", err)
	}

	return storage, nil
}

// initialize initialise le système de stockage
func (s *Storage) initialize() error {
	switch s.config.Type {
	case "json":
		return s.initializeJSON()
	case "sqlite":
		return s.initializeSQLite()
	default:
		return fmt.Errorf("type de stockage non supporté: %s", s.config.Type)
	}
}

// initializeJSON initialise le stockage JSON
func (s *Storage) initializeJSON() error {
	if _, err := os.Stat(s.config.Path); os.IsNotExist(err) {
		// Créer le fichier avec une structure vide
		data := &AlertsData{
			Alerts:    []*Alert{},
			LastSaved: time.Now(),
			Version:   "1.0.0",
		}

		return s.saveJSON(data)
	}
	return nil
}

// initializeSQLite initialise le stockage SQLite
func (s *Storage) initializeSQLite() error {
	// TODO: Implémenter le support SQLite
	return fmt.Errorf("support SQLite pas encore implémenté")
}

// StoreAlert stocke une nouvelle alerte
func (s *Storage) StoreAlert(alert *Alert) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	switch s.config.Type {
	case "json":
		return s.storeAlertJSON(alert)
	case "sqlite":
		return s.storeAlertSQLite(alert)
	default:
		return fmt.Errorf("type de stockage non supporté: %s", s.config.Type)
	}
}

// storeAlertJSON stocke une alerte dans un fichier JSON
func (s *Storage) storeAlertJSON(alert *Alert) error {
	// Charger les données existantes
	data, err := s.loadJSON()
	if err != nil {
		return fmt.Errorf("erreur lors du chargement des données: %w", err)
	}

	// Ajouter la nouvelle alerte
	data.Alerts = append(data.Alerts, alert)
	data.LastSaved = time.Now()

	// Nettoyer les anciennes alertes si nécessaire
	if err := s.cleanupOldAlerts(data); err != nil {
		return fmt.Errorf("erreur lors du nettoyage: %w", err)
	}

	// Sauvegarder
	return s.saveJSON(data)
}

// storeAlertSQLite stocke une alerte dans SQLite
func (s *Storage) storeAlertSQLite(alert *Alert) error {
	// TODO: Implémenter le stockage SQLite
	return fmt.Errorf("support SQLite pas encore implémenté")
}

// GetAlerts récupère les dernières alertes
func (s *Storage) GetAlerts(limit int) ([]*Alert, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	switch s.config.Type {
	case "json":
		return s.getAlertsJSON(limit)
	case "sqlite":
		return s.getAlertsSQLite(limit)
	default:
		return nil, fmt.Errorf("type de stockage non supporté: %s", s.config.Type)
	}
}

// getAlertsJSON récupère les alertes depuis JSON
func (s *Storage) getAlertsJSON(limit int) ([]*Alert, error) {
	data, err := s.loadJSON()
	if err != nil {
		return nil, fmt.Errorf("erreur lors du chargement des données: %w", err)
	}

	// Trier par timestamp décroissant
	sort.Slice(data.Alerts, func(i, j int) bool {
		return data.Alerts[i].Timestamp.After(data.Alerts[j].Timestamp)
	})

	// Limiter le nombre de résultats
	if limit > 0 && limit < len(data.Alerts) {
		return data.Alerts[:limit], nil
	}

	return data.Alerts, nil
}

// getAlertsSQLite récupère les alertes depuis SQLite
func (s *Storage) getAlertsSQLite(limit int) ([]*Alert, error) {
	// TODO: Implémenter la récupération SQLite
	return nil, fmt.Errorf("support SQLite pas encore implémenté")
}

// GetAlertsByPattern récupère les alertes par motif
func (s *Storage) GetAlertsByPattern(pattern string, limit int) ([]*Alert, error) {
	alerts, err := s.GetAlerts(0) // Récupérer toutes les alertes
	if err != nil {
		return nil, err
	}

	var filtered []*Alert
	for _, alert := range alerts {
		if alert.Pattern == pattern {
			filtered = append(filtered, alert)
		}
	}

	// Limiter le nombre de résultats
	if limit > 0 && limit < len(filtered) {
		return filtered[:limit], nil
	}

	return filtered, nil
}

// GetAlertsBySeverity récupère les alertes par sévérité
func (s *Storage) GetAlertsBySeverity(severity string, limit int) ([]*Alert, error) {
	alerts, err := s.GetAlerts(0) // Récupérer toutes les alertes
	if err != nil {
		return nil, err
	}

	var filtered []*Alert
	for _, alert := range alerts {
		if alert.Severity == severity {
			filtered = append(filtered, alert)
		}
	}

	// Limiter le nombre de résultats
	if limit > 0 && limit < len(filtered) {
		return filtered[:limit], nil
	}

	return filtered, nil
}

// GetStats retourne les statistiques de stockage
func (s *Storage) GetStats() (map[string]interface{}, error) {
	alerts, err := s.GetAlerts(0)
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_alerts": len(alerts),
		"by_severity":  make(map[string]int),
		"by_pattern":   make(map[string]int),
		"by_channel":   make(map[string]int),
	}

	severityStats := stats["by_severity"].(map[string]int)
	patternStats := stats["by_pattern"].(map[string]int)
	channelStats := stats["by_channel"].(map[string]int)

	for _, alert := range alerts {
		severityStats[alert.Severity]++
		patternStats[alert.Pattern]++
		
		for _, channel := range alert.Channels {
			channelStats[channel]++
		}
	}

	return stats, nil
}

// loadJSON charge les données depuis le fichier JSON
func (s *Storage) loadJSON() (*AlertsData, error) {
	file, err := os.ReadFile(s.config.Path)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la lecture du fichier: %w", err)
	}

	var data AlertsData
	if err := json.Unmarshal(file, &data); err != nil {
		return nil, fmt.Errorf("erreur lors du parsing JSON: %w", err)
	}

	return &data, nil
}

// saveJSON sauvegarde les données dans le fichier JSON
func (s *Storage) saveJSON(data *AlertsData) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("erreur lors de la sérialisation JSON: %w", err)
	}

	if err := os.WriteFile(s.config.Path, jsonData, 0644); err != nil {
		return fmt.Errorf("erreur lors de l'écriture du fichier: %w", err)
	}

	return nil
}

// cleanupOldAlerts nettoie les anciennes alertes selon la configuration
func (s *Storage) cleanupOldAlerts(data *AlertsData) error {
	if s.config.MaxAge <= 0 {
		return nil
	}

	cutoff := time.Now().AddDate(0, 0, -s.config.MaxAge)
	var filtered []*Alert

	for _, alert := range data.Alerts {
		if alert.Timestamp.After(cutoff) {
			filtered = append(filtered, alert)
		}
	}

	data.Alerts = filtered
	return nil
}

// Cleanup nettoie manuellement les anciennes alertes
func (s *Storage) Cleanup() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	switch s.config.Type {
	case "json":
		data, err := s.loadJSON()
		if err != nil {
			return err
		}
		
		if err := s.cleanupOldAlerts(data); err != nil {
			return err
		}
		
		return s.saveJSON(data)
	case "sqlite":
		// TODO: Implémenter le nettoyage SQLite
		return fmt.Errorf("support SQLite pas encore implémenté")
	default:
		return fmt.Errorf("type de stockage non supporté: %s", s.config.Type)
	}
}
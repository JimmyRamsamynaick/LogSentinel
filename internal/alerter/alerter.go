package alerter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"sync"
	"time"

	"github.com/JimmyRamsamynaick/LogSentinel/internal/storage"
	"github.com/JimmyRamsamynaick/LogSentinel/pkg/config"
)

// Alerter représente le système d'alertes
type Alerter struct {
	config  *config.Config
	storage *storage.Storage
	client  *http.Client
	mutex   sync.RWMutex
}

// Match représente une correspondance (importée du detector)
type Match struct {
	FilePath  string    `json:"file_path"`
	Line      string    `json:"line"`
	Pattern   string    `json:"pattern"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

// New crée une nouvelle instance d'Alerter
func New(cfg *config.Config) (*Alerter, error) {
	storage, err := storage.New(cfg.Storage)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'initialisation du stockage: %w", err)
	}

	return &Alerter{
		config:  cfg,
		storage: storage,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// Start démarre le système d'alertes
func (a *Alerter) Start() error {
	fmt.Println("📢 Système d'alertes démarré")
	return nil
}

// Stop arrête le système d'alertes
func (a *Alerter) Stop() {
	fmt.Println("📢 Arrêt du système d'alertes")
}

// SendAlert envoie une alerte via tous les canaux configurés
func (a *Alerter) SendAlert(match *Match) {
	alert := &storage.Alert{
		ID:        generateAlertID(),
		FilePath:  match.FilePath,
		Line:      match.Line,
		Pattern:   match.Pattern,
		Severity:  match.Severity,
		Timestamp: match.Timestamp,
		Sent:      false,
		Channels:  []string{},
	}

	// Envoyer via console (déjà fait dans le detector)
	if a.config.Alerts.Console.Enabled {
		alert.Channels = append(alert.Channels, "console")
	}

	// Envoyer via email
	if a.config.Alerts.Email.Enabled {
		if err := a.sendEmailAlert(alert); err != nil {
			fmt.Printf("❌ Erreur lors de l'envoi de l'email: %v\n", err)
		} else {
			alert.Channels = append(alert.Channels, "email")
		}
	}

	// Envoyer via webhook
	if a.config.Alerts.Webhook.Enabled {
		if err := a.sendWebhookAlert(alert); err != nil {
			fmt.Printf("❌ Erreur lors de l'envoi du webhook: %v\n", err)
		} else {
			alert.Channels = append(alert.Channels, "webhook")
		}
	}

	alert.Sent = len(alert.Channels) > 0

	// Stocker l'alerte
	if err := a.storage.StoreAlert(alert); err != nil {
		fmt.Printf("❌ Erreur lors du stockage de l'alerte: %v\n", err)
	}
}

// sendEmailAlert envoie une alerte par email
func (a *Alerter) sendEmailAlert(alert *storage.Alert) error {
	cfg := a.config.Alerts.Email

	// Construire le message
	subject := fmt.Sprintf("🚨 LogSentinel Alert - %s (%s)", alert.Pattern, alert.Severity)
	body := fmt.Sprintf(`
LogSentinel Alert

Fichier: %s
Motif: %s (%s)
Heure: %s
Ligne: %s

---
LogSentinel par Jimmy Ramsamynaick
`, alert.FilePath, alert.Pattern, alert.Severity, alert.Timestamp.Format("2006-01-02 15:04:05"), alert.Line)

	// Construire le message SMTP
	msg := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", 
		cfg.To[0], subject, body)

	// Authentification SMTP
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPServer[:len(cfg.SMTPServer)-4]) // Enlever le port

	// Envoyer l'email
	addr := cfg.SMTPServer
	if cfg.Port != 0 {
		addr = fmt.Sprintf("%s:%d", cfg.SMTPServer[:len(cfg.SMTPServer)-4], cfg.Port)
	}

	return smtp.SendMail(addr, auth, cfg.From, cfg.To, []byte(msg))
}

// sendWebhookAlert envoie une alerte via webhook
func (a *Alerter) sendWebhookAlert(alert *storage.Alert) error {
	cfg := a.config.Alerts.Webhook

	// Préparer le payload
	payload := map[string]interface{}{
		"alert_id":   alert.ID,
		"file_path": alert.FilePath,
		"pattern":   alert.Pattern,
		"severity":  alert.Severity,
		"timestamp": alert.Timestamp.Format(time.RFC3339),
		"line":      alert.Line,
		"source":    "LogSentinel",
	}

	// Sérialiser en JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("erreur lors de la sérialisation JSON: %w", err)
	}

	// Créer la requête HTTP
	req, err := http.NewRequest(cfg.Method, cfg.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("erreur lors de la création de la requête: %w", err)
	}

	// Ajouter les headers
	for key, value := range cfg.Headers {
		req.Header.Set(key, value)
	}

	// Envoyer la requête
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("erreur lors de l'envoi du webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook retourné avec le code de statut: %d", resp.StatusCode)
	}

	return nil
}

// GetAlerts récupère les alertes stockées
func (a *Alerter) GetAlerts(limit int) ([]*storage.Alert, error) {
	return a.storage.GetAlerts(limit)
}

// GetAlertsByPattern récupère les alertes par motif
func (a *Alerter) GetAlertsByPattern(pattern string, limit int) ([]*storage.Alert, error) {
	return a.storage.GetAlertsByPattern(pattern, limit)
}

// GetAlertsBySeverity récupère les alertes par sévérité
func (a *Alerter) GetAlertsBySeverity(severity string, limit int) ([]*storage.Alert, error) {
	return a.storage.GetAlertsBySeverity(severity, limit)
}

// GetStats retourne les statistiques des alertes
func (a *Alerter) GetStats() map[string]interface{} {
	stats, err := a.storage.GetStats()
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}
	return stats
}

// generateAlertID génère un ID unique pour l'alerte
func generateAlertID() string {
	return fmt.Sprintf("alert_%d", time.Now().UnixNano())
}

// TestEmail teste la configuration email
func (a *Alerter) TestEmail() error {
	if !a.config.Alerts.Email.Enabled {
		return fmt.Errorf("les alertes email ne sont pas activées")
	}

	testAlert := &storage.Alert{
		ID:        "test_alert",
		FilePath:  "/test/path",
		Line:      "Test line for LogSentinel email configuration",
		Pattern:   "test",
		Severity:  "low",
		Timestamp: time.Now(),
	}

	return a.sendEmailAlert(testAlert)
}

// TestWebhook teste la configuration webhook
func (a *Alerter) TestWebhook() error {
	if !a.config.Alerts.Webhook.Enabled {
		return fmt.Errorf("les webhooks ne sont pas activés")
	}

	testAlert := &storage.Alert{
		ID:        "test_alert",
		FilePath:  "/test/path",
		Line:      "Test line for LogSentinel webhook configuration",
		Pattern:   "test",
		Severity:  "low",
		Timestamp: time.Now(),
	}

	return a.sendWebhookAlert(testAlert)
}
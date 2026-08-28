package handlers

func init() {
	// Handler tests exercise persistence and responses, not background monitoring.
	restartMonitoring = func() {}
}

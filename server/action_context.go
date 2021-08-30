package main

// ActionContext passed from action buttons
type ActionContext struct {
	AccessToken string `json:"access_token"`
	Status      string `json:"status"`
	Result      string `json:"result"`
	UserID      string `json:"user_id"`
}

// Action type for decoding action buttons
type Action struct {
	UserID  string         `json:"user_id"`
	Context *ActionContext `json:"context"`
}

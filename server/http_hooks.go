package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mattermost/mattermost-server/v6/model"
	"github.com/mattermost/mattermost-server/v6/plugin"
)

// ServeHTTP allows the plugin to implement the http.Handler interface. Requests destined for the
// /plugins/{id} path will be routed to the plugin.
func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/auth":
		p.handleAuth(c, w, r)
	case "/callback":
		p.handleCallback(c, w, r)
	default:
		http.NotFound(w, r)
	}
}

type AuthRequest struct {
	BindingMessage    string `json:"binding_message"`
	LoginHint         string `json:"login_hint"`
	IsConsentRequired bool   `json:"is_consent_required"`
	ACRValues         string `json:"acr_values"`
	Scope             string `json:"scope"`
	AccessToken       string `json:"access_token"`
}

func (p *Plugin) handleAuth(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	// Verify request from keycloak

	// Mattermost remove authorization header
	// authzHeader := r.Header.Get("Authorization")
	// if authzHeader == "" || !strings.HasPrefix(authzHeader, "Bearer ") {
	// 	p.responseError(w, http.StatusBadRequest, "invalid_request", "No authorization header")
	// 	return
	// }
	// accessToken := authzHeader[len("Bearer "):]

	var authReq *AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil || authReq == nil {
		p.responseError(w, http.StatusBadRequest, "invalid_request", "We could not decode the authRequest")
		return
	}

	// TODO need to verify the access token by the public key from keycloak
	accessToken := authReq.AccessToken

	// Render message
	user, err := p.API.GetUserByUsername(authReq.LoginHint)
	if err != nil {
		p.API.LogError("Unable to get user by username err=" + err.Error())
		p.responseError(w, http.StatusBadRequest, "invalid_request", "We could not find the user")
		return
	}

	channel, appError := p.API.GetDirectChannel(user.Id, p.botUserID)

	if appError != nil {
		p.API.LogError("Unable to get direct channel for bot err=" + appError.Error())
		p.responseError(w, http.StatusBadRequest, "invalid_request", "We could not find the user")
		return
	}
	if channel == nil {
		p.API.LogError("Could not get direct channel for bot and user_id=%s", user.Id)
		p.responseError(w, http.StatusBadRequest, "invalid_request", "We could not find the user")
		return
	}
	post := &model.Post{
		ChannelId: channel.Id,
		UserId:    p.botUserID,
	}

	bms := strings.Split(authReq.BindingMessage, ",")
	requestor := bms[0]
	target := bms[1]

	post.SetProps(map[string]interface{}{
		"attachments": []*model.SlackAttachment{
			{
				Text: "@" + requestor + " より要求: " + target,
				Actions: []*model.PostAction{
					{
						Id:   "approve",
						Name: "承認",
						Integration: &model.PostActionIntegration{
							Context: map[string]interface{}{
								"access_token": accessToken,
								"status":       "SUCCEED",
								"result":       "@" + requestor + " の要求を承認: " + target,
							},
							URL: fmt.Sprintf("%v/plugins/%v/callback", p.getSiteURL(), manifest.ID),
						},
					},
					{
						Id:    "reject",
						Name:  "却下",
						Style: "danger",
						Integration: &model.PostActionIntegration{
							Context: map[string]interface{}{
								"access_token": accessToken,
								"status":       "UNAUTHORIZED",
								"result":       "@" + requestor + "の要求を却下: " + target,
							},
							URL: fmt.Sprintf("%v/plugins/%v/callback", p.getSiteURL(), manifest.ID),
						},
					},
				},
			},
		},
	})

	if _, err := p.API.CreatePost(post); err != nil {
		p.API.LogError(
			"We could not create the post",
			"user_id", post.UserId,
			"err", err.Error(),
		)
	}

	// Need to return 201
	w.WriteHeader(http.StatusCreated)
}

func (p *Plugin) handleCallback(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	var action *Action
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil || action == nil {
		p.encodeEphemeralMessage(w, "We could not decode the action")
		return
	}

	// Verify http header
	// https://developers.mattermost.com/integrate/plugins/server/best-practices/
	mattermostUserID := r.Header.Get("Mattermost-User-Id")
	if mattermostUserID == "" {
		p.API.LogError("http request not authenticated: no Mattermost-User-Id")
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	// call ciba callback
	jsonValue := toPostJSON(action)

	req, err := http.NewRequest("POST", p.getConfiguration().CallbackURL, bytes.NewBuffer(jsonValue))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+action.Context.AccessToken)

	client := &http.Client{Timeout: time.Duration(10) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		p.API.LogError("Failed to request keycloak ciba callback", err)
		p.encodeEphemeralMessage(w, "We could not send the action")
		return
	}

	defer resp.Body.Close()

	// response mattermost
	w.Header().Set("Content-Type", "application/json")

	actionResp := model.PostActionIntegrationResponse{
		Update: &model.Post{
			Message: action.Context.Result,
		},
	}
	actionResp.Update.SetProps(model.StringInterface{})

	b, _ := json.Marshal(actionResp)

	if _, err := w.Write(b); err != nil {
		p.API.LogWarn("failed to write PostActionIntegrationResponse")
	}
}

func toPostJSON(action *Action) []byte {
	switch action.Context.Status {
	case "SUCCEED":
		return []byte(`{"status": "SUCCEED"}`)
	case "UNAUTHORIZED":
		return []byte(`{"status": "UNAUTHORIZED"}`)
	case "CANCELLED":
		return []byte(`{"status": "CANCELLED"}`)
	default:
		return []byte(`{"status": "UNAUTHORIZED"}`)
	}
}

func (p *Plugin) responseError(w http.ResponseWriter, code int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	resp := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}{
		Error:            errorCode,
		ErrorDescription: message,
	}

	b, _ := json.Marshal(resp)

	if _, err := w.Write(b); err != nil {
		p.API.LogWarn("failed to write error response")
	}
}

func (p *Plugin) encodeEphemeralMessage(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")

	resp := model.PostActionIntegrationResponse{
		EphemeralText: message,
	}

	if _, err := w.Write(resp.ToJson()); err != nil {
		p.API.LogWarn("failed to write PostActionIntegrationResponse")
	}
}

func (p *Plugin) getSiteURL() string {
	siteURL := "http://localhost:8065"

	config := p.API.GetConfig()

	if config == nil || config.ServiceSettings.SiteURL == nil || len(*config.ServiceSettings.SiteURL) == 0 {
		return siteURL
	}

	return *config.ServiceSettings.SiteURL
}

package tokens

import (
	"strings"
	"testing"
)

func TestRetiredModels(t *testing.T) {
	for _, model := range []string{
		"babbage-002",
		"chatgpt-4o-latest",
		"davinci-002",
		"gpt-3.5-turbo",
		"gpt-3.5-turbo-0125",
		"gpt-3.5-turbo-1106",
		"gpt-3.5-turbo-16k",
		"gpt-3.5-turbo-instruct",
		"gpt-3.5-turbo-instruct-0914",
		"gpt-4",
		"gpt-4-0613",
		"gpt-4-turbo",
		"gpt-4-turbo-2024-04-09",
		"gpt-4.1-nano",
		"gpt-4.1-nano-2025-04-14",
		"gpt-4o-2024-05-13",
		"gpt-5-chat-latest",
		"gpt-5-codex",
		"gpt-5.1-chat-latest",
		"gpt-5.1-codex",
		"gpt-5.1-codex-max",
		"gpt-5.1-codex-mini",
		"gpt-5.2-chat-latest",
		"gpt-5.2-codex",
		"gpt-5.3-chat-latest",
		"gpt-audio-mini-2025-10-06",
		"gpt-image-1",
		"o1",
		"o1-2024-12-17",
		"o1-pro",
		"o1-pro-2025-03-19",
		"o3-deep-research",
		"o3-deep-research-2025-06-26",
		"o3-mini",
		"o3-mini-2025-01-31",
		"o4-mini",
		"o4-mini-2025-04-16",
		"o4-mini-deep-research",
		"o4-mini-deep-research-2025-06-26",
		"sora-2",
		"sora-2-pro",
	} {
		for _, id := range []string{model, strings.ToUpper(model), "openai/" + model, "ft:" + model + ":org:custom:123", "openai/ft:" + model + ":org:custom:123"} {
			for _, patterns := range [][]string{nil, {"*"}, {id}, {id + "*"}} {
				if (&Principal{Models: patterns}).AllowsModel(id) {
					t.Errorf("retired %q allowed by %v", id, patterns)
				}
			}
		}
	}
	for _, model := range []string{
		"gpt-4o", "gpt-4.1", "gpt-4.1-mini", "gpt-image-1-mini", "o3",
		"ft:gpt-4o-mini-2024-07-18:org:gpt-4:abc",
		"openai/ft:gpt-4o-mini-2024-07-18:org:gpt-4:abc",
	} {
		if !ModelEligible(model) {
			t.Errorf("active model %q excluded", model)
		}
	}
}

func TestCyberModels(t *testing.T) {
	for _, model := range []string{"gpt-5.6-cyber", "CYBER", "gpt-CyBeR2", "cybermodel", "modelcyber", "ft:gpt-4o:org:cyber:123"} {
		for _, patterns := range [][]string{nil, {"*"}, {model}, {model + "*"}} {
			if (&Principal{Models: patterns}).AllowsModel(model) {
				t.Errorf("cyber %q allowed by %v", model, patterns)
			}
		}
	}
}

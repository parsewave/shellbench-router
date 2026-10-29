package tokens

import "strings"

// Known retired OpenAI IDs from the published shutdown schedule:
// https://developers.openai.com/api/docs/deprecations
// The legacy instruct-0914 snapshot follows its retired instruct family.
// Keep exact IDs: active siblings such as gpt-image-1-mini must remain usable.
var retiredModels = map[string]bool{
	"babbage-002":                      true,
	"chatgpt-4o-latest":                true,
	"davinci-002":                      true,
	"gpt-3.5-turbo":                    true,
	"gpt-3.5-turbo-0125":               true,
	"gpt-3.5-turbo-1106":               true,
	"gpt-3.5-turbo-16k":                true,
	"gpt-3.5-turbo-instruct":           true,
	"gpt-3.5-turbo-instruct-0914":      true,
	"gpt-4":                            true,
	"gpt-4-0613":                       true,
	"gpt-4-turbo":                      true,
	"gpt-4-turbo-2024-04-09":           true,
	"gpt-4.1-nano":                     true,
	"gpt-4.1-nano-2025-04-14":          true,
	"gpt-4o-2024-05-13":                true,
	"gpt-5-chat-latest":                true,
	"gpt-5-codex":                      true,
	"gpt-5.1-chat-latest":              true,
	"gpt-5.1-codex":                    true,
	"gpt-5.1-codex-max":                true,
	"gpt-5.1-codex-mini":               true,
	"gpt-5.2-chat-latest":              true,
	"gpt-5.2-codex":                    true,
	"gpt-5.3-chat-latest":              true,
	"gpt-audio-mini-2025-10-06":        true,
	"gpt-image-1":                      true,
	"o1":                               true,
	"o1-2024-12-17":                    true,
	"o1-pro":                           true,
	"o1-pro-2025-03-19":                true,
	"o3-deep-research":                 true,
	"o3-deep-research-2025-06-26":      true,
	"o3-mini":                          true,
	"o3-mini-2025-01-31":               true,
	"o4-mini":                          true,
	"o4-mini-2025-04-16":               true,
	"o4-mini-deep-research":            true,
	"o4-mini-deep-research-2025-06-26": true,
	"sora-2":                           true,
	"sora-2-pro":                       true,
}

// ModelEligible applies global exclusions even to unrestricted clients.
func ModelEligible(m string) bool {
	m = strings.ToLower(m)
	if strings.Contains(m, "cyber") {
		return false
	}
	// Non-letter boundaries catch beta2 without excluding stable "latest" IDs.
	for _, label := range strings.FieldsFunc(m, func(r rune) bool { return r < 'a' || r > 'z' }) {
		switch label {
		case "alpha", "beta", "test", "testing", "exp", "experiment", "experimental", "preview", "daybreak":
			return false
		}
	}
	// Provider namespaces and fine-tune bases must not bypass retirement.
	// Fine-tune organization/custom suffixes are not model selectors.
	base := m[strings.LastIndexByte(m, '/')+1:]
	base = strings.TrimPrefix(base, "ft:")
	base, _, _ = strings.Cut(base, ":")
	return !retiredModels[base]
}

package llm

import (
	"context"
	"fmt"

	"infralens/internal/settings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	brTypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

// bedrock uses the AWS credentials of a profile, so no separate key is
// needed and the prompt stays inside an AWS account. This client is separate
// from the read-only audit client: inference is not a Describe/List/Get call,
// and it must not be mistaken for access to the audited account.
type bedrock struct {
	model string
	cli   *bedrockruntime.Client
}

func newBedrock(cfg settings.LLM, model string) (Provider, error) {
	if model == "" {
		return nil, fmt.Errorf("bedrock needs a model id")
	}
	opts := []func(*config.LoadOptions) error{}
	if cfg.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(cfg.Profile))
	}
	if cfg.Region != "" {
		opts = append(opts, config.WithRegion(cfg.Region))
	}
	c, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}
	return &bedrock{model: model, cli: bedrockruntime.NewFromConfig(c)}, nil
}

func (b *bedrock) Name() string { return "bedrock:" + b.model }
func (b *bedrock) Local() bool  { return false }
func (b *bedrock) Complete(ctx context.Context, system, user string) (string, error) {
	out, err := b.cli.Converse(ctx, &bedrockruntime.ConverseInput{
		ModelId: aws.String(b.model),
		System:  []brTypes.SystemContentBlock{&brTypes.SystemContentBlockMemberText{Value: system}},
		Messages: []brTypes.Message{{
			Role:    brTypes.ConversationRoleUser,
			Content: []brTypes.ContentBlock{&brTypes.ContentBlockMemberText{Value: user}},
		}},
		InferenceConfig: &brTypes.InferenceConfiguration{Temperature: aws.Float32(0.2), MaxTokens: aws.Int32(4096)},
	})
	if err != nil {
		return "", err
	}
	msg, ok := out.Output.(*brTypes.ConverseOutputMemberMessage)
	if !ok {
		return "", fmt.Errorf("the model returned no answer")
	}
	var s string
	for _, c := range msg.Value.Content {
		if t, ok := c.(*brTypes.ContentBlockMemberText); ok {
			s += t.Value
		}
	}
	if s == "" {
		return "", fmt.Errorf("the model returned no answer")
	}
	return s, nil
}

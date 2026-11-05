# Inference providers

Motte mounts `~/.config/motte/opencode` read-only at `/etc/opencode` in every VM.
The `opencode.json` in that directory configures OpenCode in all your sandboxes; motte creates a minimal one on the first launch.
The examples below add providers to that file.
All providers can live side by side in the same `providers` section.

## Local llama.cpp

Start a llama.cpp server on the host.
Bind it to an interface the sandbox gateway can reach, for example `--host 0.0.0.0`:

```sh
llama-server -m ./model.gguf --host 0.0.0.0 --port 9931
```

Egress from the VM is deny-by-default, so allow the host port in your network policy:

```sh
motte policies configure global
```

```yaml
network:
  allow:
    - "host:tcp:9931"
```

Add the provider to `~/.config/motte/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "providers": {
    "llama": {
      "name": "Llama server (host)",
      "package": "@opencode/ai/providers/openai-compatible",
      "settings": {
        "baseURL": "http://host.microsandbox.internal:9931/v1",
      }
    }
  }
}
```


## OpenCode Go

Create an API key at https://opencode.ai/console.
Store it as a secret, so the key's value never enters the VM:

```sh
motte secrets add
```

Enter `OPENCODE_GO_KEY` as the name and `*.opencode.ai` as the allowed hosts, then paste the key.

Add the provider to `~/.config/motte/opencode/opencode.json` and reference the key as `{env:OPENCODE_GO_KEY}` in `settings.apiKey`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "go/glm-5.3",
  "providers": {
    "go": {
      "name": "OpenCode Go",
      "package": "aisdk:@ai-sdk/openai-compatible",
      "settings": {
        "baseURL": "https://opencode.ai/zen/go/v1",
        "apiKey": "{env:OPENCODE_GO_KEY}"
      },
      "models": {
        "glm-5.3": { "name": "GLM-5.3" },
        "glm-5.3-flash": { "name": "GLM-5.3 Flash" }
      }
    }
  }
}
```

Launch the sandbox with `motte oc <profile>`.

## Proxies and gateways

Any OpenAI-compatible proxy works as a custom provider, with its API key read from the environment.
Store the key as a secret named `LLM_API_KEY`, and enter the proxy's hostname as the allowed hosts:

```sh
motte secrets add
```

To route a OpenCode built-in provider through a proxy, override only its endpoint and key:

```json
{
  "providers": {
    "anthropic": {
      "settings": {
        "baseURL": "https://llm-proxy.example.com/anthropic",
        "apiKey": "{env:LLM_API_KEY}"
      }
    }
  }
}
```

An unset variable becomes an empty string, so a missing secret shows up as an authentication error.


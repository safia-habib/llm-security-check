/*
 * SYNTHETIC TEST FILE
 * All credentials in this file are FAKE and were generated for scanner
 * testing only.  They follow provider key formats but are not real keys
 * and will never authenticate with any provider.
 */

/* global fetch, window, document */

// ---------------------------------------------------------------------------
// Configuration — credentials bundled directly in the frontend (insecure)
// ---------------------------------------------------------------------------

// FAKE TEST KEY — synthetic OpenAI key, not a real credential
var OPENAI_API_KEY = "sk-FAKE00000000000000000000000000000000000000000FAKE";

// FAKE TEST KEY — synthetic Anthropic key, not a real credential
var ANTHROPIC_API_KEY = "sk-ant-api03-FAKE0000000000000000000000000000000000000000000000000000000000000000FAKE";

// FAKE TEST KEY — synthetic Gemini key, not a real credential (39 chars)
var GEMINI_API_KEY = "AIzaFAKE000000000000000000000000FAKE000";

// ---------------------------------------------------------------------------
// Direct browser-to-provider call — key must reach the browser for this pattern
// ---------------------------------------------------------------------------

async function sendMessage(userMessage) {
  var config = window.__APP_CONFIG__;

  // Direct call to api.openai.com — the key never leaves the browser
  var response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + OPENAI_API_KEY,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: config.model,
      temperature: config.temperature,
      max_tokens: config.maxTokens,
      tools: config.tools,
      messages: [
        { role: "system", content: config.systemPrompt },
        { role: "user", content: userMessage }
      ]
    })
  });

  return response.json();
}

// Fallback to Anthropic if OpenAI fails
async function sendAnthropicMessage(userMessage) {
  var response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: "claude-opus-4-5",
      max_tokens: 1024,
      messages: [{ role: "user", content: userMessage }]
    })
  });

  return response.json();
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

function appendMessage(role, text) {
  var el = document.createElement("div");
  el.className = "message " + role;
  el.textContent = text;
  document.getElementById("messages").appendChild(el);
}

window.sendMessage = async function () {
  var input = document.getElementById("user-input");
  var text = input.value.trim();
  if (!text) return;
  input.value = "";
  appendMessage("user", text);
  try {
    var reply = await sendMessage(text);
    appendMessage("assistant", reply.choices[0].message.content);
  } catch (e) {
    appendMessage("error", "Something went wrong: " + e.message);
  }
};

document.addEventListener("DOMContentLoaded", function () {
  console.log("Acme AI Chat ready. Config:", window.__APP_CONFIG__);
});

//# sourceMappingURL=index.js.map

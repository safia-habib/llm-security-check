/*
 * Secure chat frontend — all LLM calls go through the backend proxy at /api/chat.
 * No API keys, no provider URLs, no system prompts in this file.
 */

/* global fetch, document */

async function sendMessage(userMessage) {
  // Correct pattern: call the same-origin backend proxy, not the provider directly.
  // The backend holds the API key in an environment variable, never shipped to the browser.
  const response = await fetch("/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: userMessage })
  });

  if (!response.ok) {
    throw new Error("Request failed: " + response.status);
  }

  return response.json();
}

function appendMessage(role, text) {
  const el = document.createElement("div");
  el.className = "message " + role;
  el.textContent = text;
  document.getElementById("messages").appendChild(el);
}

window.sendMessage = async function () {
  const input = document.getElementById("user-input");
  const text = input.value.trim();
  if (!text) return;
  input.value = "";
  appendMessage("user", text);
  try {
    const reply = await sendMessage(text);
    appendMessage("assistant", reply.message);
  } catch (e) {
    appendMessage("error", "Something went wrong. Please try again.");
  }
};

document.addEventListener("DOMContentLoaded", function () {
  console.log("Acme AI Chat ready.");
});

const status = document.getElementById("status");
document.getElementById("pair").addEventListener("submit", async event => {
  event.preventDefault();
  const token = document.getElementById("token").value.trim();
  const port = Number(document.getElementById("port").value);
  try {
    const response = await fetch(`http://127.0.0.1:${port}/status`, {
      headers: {Authorization: `Bearer ${token}`}, signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    await chrome.storage.local.set({token, port});
    document.getElementById("token").value = "";
    status.textContent = "Подключено. Управление — в консоли Pathfinder.";
  } catch (error) { status.textContent = `Не удалось подключиться: ${error.message}`; }
});
document.getElementById("disconnect").addEventListener("click", async () => {
  await chrome.storage.local.remove(["token", "port"]);
  await chrome.storage.session.clear();
  status.textContent = "Отключено.";
});

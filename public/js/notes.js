function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
 
function noteCard(note) {
  // FIX (XSS): every value that originated from user input is passed through
  // escapeHtml before being placed into the HTML template string.
  // Previously these values were interpolated raw, which allowed a note whose
  // title or body contained script tags to execute arbitrary JavaScript in any
  // viewer's browser (stored XSS).
  return `
    <article class="note-card">
      <h3>${escapeHtml(note.title)}</h3>
      <p class="note-meta">Owner: ${escapeHtml(note.ownerUsername)} | ID: ${escapeHtml(String(note.id))} | Pinned: ${escapeHtml(String(note.pinned))}</p>
      <div class="note-body">${escapeHtml(note.body)}</div>
    </article>
  `;
}
 
async function loadNotes(ownerId, search) {
  const query = new URLSearchParams();
  if (ownerId) {
    query.set("ownerId", ownerId);
  }
  if (search) {
    query.set("search", search);
  }
  const result = await api(`/api/notes?${query.toString()}`);
  const notesList = document.getElementById("notes-list");
  notesList.innerHTML = result.notes.map(noteCard).join("");
}
 
(async function bootstrapNotes() {
  try {
    const user = await loadCurrentUser();
    if (!user) {
      document.getElementById("notes-list").textContent = "Please log in first.";
      return;
    }
    document.getElementById("notes-owner-id").value = user.id;
    document.getElementById("create-owner-id").value = user.id;
    await loadNotes(user.id, "");
  } catch (error) {
    document.getElementById("notes-list").textContent = error.message;
  }
})();
 
document.getElementById("search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  await loadNotes(formData.get("ownerId"), formData.get("search"));
});
 
document.getElementById("create-note-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const payload = {
    ownerId: formData.get("ownerId"),
    title: formData.get("title"),
    body: formData.get("body"),
    pinned: formData.get("pinned") === "on"
  };
  await api("/api/notes", {
    method: "POST",
    body: JSON.stringify(payload)
  });
  await loadNotes(payload.ownerId, "");
  event.currentTarget.reset();
  document.getElementById("create-owner-id").value = payload.ownerId;
});
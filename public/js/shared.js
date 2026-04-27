(async function bootstrapAdmin() {
  try {
    const user = await loadCurrentUser();
    if (!user) {
      document.getElementById("admin-warning").textContent = "Please log in first.";
      return;
    }
    
    if (user.role !== "admin") {
      document.getElementById("admin-warning").textContent =
        "Access denied.";
      return;
    } else {
      document.getElementById("admin-warning").textContent = "Authenticated as admin.";
    }
    const result = await api("/api/admin/users");
    document.getElementById("admin-users").innerHTML = result.users
      .map(
        (entry) => `
          <tr>
            <td>${entry.id}</td>
            <td>${entry.username}</td>
            <td>${entry.role}</td>
            <td>${entry.displayName}</td>
            <td>${entry.noteCount}</td>
          </tr>
        `
      )
      .join("");
  } catch (error) {
    document.getElementById("admin-warning").textContent = error.message;
  }
})();
 
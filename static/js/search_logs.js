function showCode(content) {
  document.getElementById("modalCodeContent").textContent = content;
  const modal = new bootstrap.Modal(document.getElementById("codeModal"));
  modal.show();
}

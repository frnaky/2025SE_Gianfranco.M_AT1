function toggleCustomInput() {
  const codeLanguage = document.getElementById("code_language").value;
  const customLanguageInput = document.getElementById("custom_language");

  if (codeLanguage === "other") {
    customLanguageInput.style.display = "block";
  } else {
    customLanguageInput.style.display = "none";
  }
}

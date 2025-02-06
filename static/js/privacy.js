document.getElementById("downloadData").addEventListener("click", function () {
  fetch("/download_data", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({}),
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error("Download failed: " + response.statusText);
      }
      return response.blob();
    })
    .then((blob) => {
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "user_logs.csv";
      link.click();
    })
    .catch((error) => {
      document.getElementById("downloadError").style.display = "block";
      document.getElementById("downloadError").innerText = error.message;
    });
});

function confirmDelete() {
  const confirmed = confirm(
    "Are You Sure you want to Delete your Account.. THIS CANNOT BE UNDONE! think wisely.."
  );

  if (confirmed) {
    document.getElementById("deleteAccountForm").submit();
  }
}

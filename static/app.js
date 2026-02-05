async function generate() {
    const domain = document.getElementById("domain").value
    const email = document.getElementById("email").value

    const res = await fetch("/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, email })
    })

    const data = await res.json()
    document.getElementById("output").innerText = data.message + "\nCheck logs for DNS TXT value"
}

async function finalize() {
    const res = await fetch("/finalize")
    const text = await res.text()
    document.getElementById("output").innerText = "Finalize triggered. Check logs for certificate."
}
